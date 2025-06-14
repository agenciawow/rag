# indexador.py

import os, re, logging, asyncio
from io import BytesIO
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from dotenv import load_dotenv

import requests, voyageai, pymupdf, pymupdf4llm
from PIL import Image
from tqdm import tqdm
from astrapy import DataAPIClient
from astrapy.constants import VectorMetric
from astrapy.info import CollectionDefinition, CollectionVectorOptions
from astrapy.collection import Collection

@dataclass
class Config:
    PDF_URL: str = "https://arxiv.org/pdf/2501.13956"
    IMAGE_DIR: str = "pdf_images"
    VOYAGE_EMBEDDING_DIM: int = 1024
    MAX_TOKENS_PER_INPUT: int = 32_000
    TOKENS_PER_PIXEL: float = 1 / 560
    TOKEN_CHARS_RATIO: int = 4  # caracteres por token estimado
    CONCURRENCY: int = 5
    ERROR_ON_LIMIT: bool = True
    BATCH_SIZE: int = 100
    COLLECTION_NAME: str = "pdf_documents"
    DOWNLOAD_TIMEOUT: int = 30
    DOWNLOAD_CHUNK_SIZE: int = 8192
    PIXMAP_SCALE: int = 2

def get_config():
    """Cria configuração com valores do ambiente"""
    pdf_url = os.getenv("PDF_URL", "https://arxiv.org/pdf/2501.13956")
    return Config(PDF_URL=pdf_url)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ───── Helpers ─────
def create_doc_source_name(pdf_url: str) -> str:
    """Cria nome único para o documento baseado na URL/caminho"""
    # Se for um arquivo temporário e tiver o nome original definido
    if os.path.basename(pdf_url).startswith('temp_') and 'ORIGINAL_FILENAME' in os.environ:
        return os.environ['ORIGINAL_FILENAME']
    
    # Para URLs, usa o nome do arquivo da URL
    if pdf_url.startswith(('http://', 'https://')):
        # Extrai nome do arquivo da URL
        filename = pdf_url.split('/')[-1]
        # Remove parâmetros de query se existirem
        filename = filename.split('?')[0]
        # Remove extensão
        return os.path.splitext(filename)[0]
    
    # Para arquivos locais, usa o nome do arquivo
    return os.path.splitext(os.path.basename(pdf_url))[0]

def pixel_token_count(img: Image.Image, config: Config) -> int:
    return int((img.width * img.height) * config.TOKENS_PER_PIXEL)

def text_token_estimate(text: str, config: Config) -> int:
    return max(1, len(text) // config.TOKEN_CHARS_RATIO)

def fits_limits(txt: str, img: Image.Image, config: Config) -> bool:
    return (text_token_estimate(txt, config) + pixel_token_count(img, config)) <= config.MAX_TOKENS_PER_INPUT

def download_pdf(url: str, config: Config) -> Optional[pymupdf.Document]:
    try:
        # Verifica se é um arquivo local
        if os.path.exists(url):
            logger.info("Abrindo PDF local: %s", url)
            doc = pymupdf.open(url)
            logger.info("PDF carregado (%d páginas)", doc.page_count)
            return doc
        else:
            # Download da URL
            logger.info("Baixando PDF (streaming)…")
            with requests.get(url, stream=True, timeout=config.DOWNLOAD_TIMEOUT) as r:
                r.raise_for_status()
                buf = BytesIO()
                for chunk in r.iter_content(config.DOWNLOAD_CHUNK_SIZE):
                    buf.write(chunk)
            buf.seek(0)
            doc = pymupdf.open(stream=buf, filetype="pdf")
            logger.info("PDF baixado (%d páginas)", doc.page_count)
            return doc
    except Exception as e:
        logger.error("Falha ao processar PDF: %s", e)
        return None

def extract_page_content(pdf: pymupdf.Document, n: int,
                         src: str, img_dir: str, config: Config) -> Optional[Dict]:
    try:
        page = pdf[n]
        md = pymupdf4llm.to_markdown(pdf, pages=[n])
        pix = page.get_pixmap(matrix=pymupdf.Matrix(config.PIXMAP_SCALE, config.PIXMAP_SCALE))
        img_path = os.path.join(img_dir, f"{src}_page_{n+1}.png")
        pix.save(img_path)
        return {"id": f"{src}_{n}", "page_num": n+1, "markdown_text": md,
                "image_path": img_path, "doc_source": src}
    except Exception as e:
        logger.error("Erro página %d: %s", n+1, e)
        return None

def validate_env_vars() -> None:
    """Valida se todas as variáveis de ambiente necessárias estão definidas"""
    required_vars = [
        "VOYAGE_API_KEY",
        "VECTOR_DB_API_ENDPOINT", 
        "VECTOR_DB_TOKEN"
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        raise RuntimeError(
            f"Variáveis de ambiente ausentes: {', '.join(missing_vars)}"
        )

def connect_to_astra(config: Config) -> Collection:
    """Conecta ao Astra DB e retorna a collection"""
    try:
        endpoint = os.getenv("VECTOR_DB_API_ENDPOINT")
        token = os.getenv("VECTOR_DB_TOKEN")
        
        if not endpoint or not token:
            raise RuntimeError("Variáveis VECTOR_DB_API_ENDPOINT e VECTOR_DB_TOKEN devem estar definidas")
        
        # Criar cliente e conectar ao database vetorial
        client = DataAPIClient(token)
        database = client.get_database_by_api_endpoint(endpoint)
        
        logger.info(f"Conectado ao database {database.info().name}")
        
        # Listar collections existentes
        existing_collections = database.list_collection_names()
        logger.info(f"Collections existentes: {existing_collections}")
        
        # Verificar se collection existe e criar se necessário
        if config.COLLECTION_NAME not in existing_collections:
            # Criar collection com configuração de vetor
            logger.info(f"Collection '{config.COLLECTION_NAME}' não existe. Criando...")
            collection_definition = CollectionDefinition(
                vector=CollectionVectorOptions(
                    dimension=config.VOYAGE_EMBEDDING_DIM,
                    metric=VectorMetric.COSINE,
                )
            )
            collection = database.create_collection(
                config.COLLECTION_NAME,
                definition=collection_definition,
            )
            logger.info(f"Collection '{config.COLLECTION_NAME}' criada com sucesso")
        else:
            logger.info(f"Collection '{config.COLLECTION_NAME}' já existe")
        
        # Sempre obter a collection (independentemente se existia ou foi criada)
        collection = database.get_collection(config.COLLECTION_NAME)
        return collection
        
    except Exception as e:
        logger.error(f"Erro ao conectar com Astra DB: {e}")
        raise

# ───── Async embedding ─────
async def embed_page(sema: asyncio.Semaphore, client: voyageai.AsyncClient,
                     doc: Dict, config: Config) -> Optional[Dict]:
    async with sema:
        try:
            img = Image.open(doc["image_path"])
            if not fits_limits(doc["markdown_text"], img, config):
                msg = f"Pág {doc['page_num']} excede limite {config.MAX_TOKENS_PER_INPUT} tokens"
                if config.ERROR_ON_LIMIT:
                    raise ValueError(msg)
                logger.error(msg); return None

            res = await client.multimodal_embed(
                inputs=[[doc["markdown_text"], img]],
                model="voyage-multimodal-3",
                input_type="document")
            vec = res.embeddings[0]
            if len(vec) != config.VOYAGE_EMBEDDING_DIM:
                raise ValueError(f"Dimensão inesperada: esperado {config.VOYAGE_EMBEDDING_DIM}, obtido {len(vec)}")
            doc["embedding"] = vec
            return doc
        except Exception as e:
            logger.error("Embedding falhou pág %d: %s", doc["page_num"], e)
            return None

# ───── Main ─────
async def main() -> None:
    load_dotenv()
    
    try:
        validate_env_vars()
    except RuntimeError as e:
        logger.error(str(e))
        return

    # Usa configuração com valores do ambiente
    config = get_config()
    
    src = create_doc_source_name(config.PDF_URL)
    logger.info("Indexando documento: %s", src)
    logger.info("PDF URL/Path: %s", config.PDF_URL)

    pdf_path = config.PDF_URL  # Store the original PDF path for cleanup
    pdf = download_pdf(config.PDF_URL, config)
    if not pdf: 
        logger.error("Não foi possível carregar o PDF")
        return
    Path(config.IMAGE_DIR).mkdir(exist_ok=True)

    docs = [c for i in tqdm(range(pdf.page_count), desc="Páginas")
            if (c := extract_page_content(pdf, i, src, config.IMAGE_DIR, config))]
    if not docs:
        logger.error("Nada extraído"); return

    logger.info("Gerando embeddings (%d concorrentes)…", config.CONCURRENCY)
    sema = asyncio.Semaphore(config.CONCURRENCY)
    async_client = voyageai.AsyncClient()
    try:
        tasks = [embed_page(sema, async_client, d, config) for d in docs]
        embedded = [d for d in await asyncio.gather(*tasks) if d]
    finally:
        # Fecha conexão HTTP do cliente
        if hasattr(async_client, "aclose"):
            await async_client.aclose()

    if not embedded:
        logger.error("Nenhum embedding gerado"); return

    # Conectar ao Astra DB
    collection = connect_to_astra(config)
    
    # Remover documentos antigos do mesmo source (só se a collection existir e tiver dados)
    try:
        del_result = collection.delete_many({"doc_source": src})
        if del_result.deleted_count > 0:
            logger.info("Removidos %d documentos antigos (%s)", del_result.deleted_count, src)
        else:
            logger.info("Nenhum documento antigo encontrado para remover (%s)", src)
    except Exception as e:
        logger.warning("Aviso ao tentar remover documentos antigos: %s", e)

    # Preparar documentos para inserção
    documents = [
        {
            "_id": d["id"],
            "page_num": d["page_num"],
            "file_path": d["image_path"],
            "doc_source": d["doc_source"],
            "markdown_text": d["markdown_text"],
            "$vector": d["embedding"]
        } for d in embedded
    ]

    # Inserir em lotes
    logger.info("Inserindo em lotes de %d…", config.BATCH_SIZE)
    inserted_count = 0
    
    def insert_document_fallback(doc: Dict, batch_idx: int, doc_idx: int) -> bool:
        """Tenta inserir documento individual como fallback"""
        try:
            collection.insert_one(doc)
            logger.debug("Documento individual inserido: %s", doc["_id"])
            return True
        except Exception as e:
            logger.error("Erro ao inserir documento individual %d do lote %d: %s", doc_idx+1, batch_idx+1, e)
            return False
    
    for i in tqdm(range(0, len(documents), config.BATCH_SIZE), desc="Astra DB"):
        batch = documents[i:i+config.BATCH_SIZE]
        batch_idx = i//config.BATCH_SIZE
        
        try:
            result = collection.insert_many(batch, ordered=False)
            inserted_count += len(result.inserted_ids)
            logger.info("Lote %d inserido com sucesso: %d documentos", batch_idx + 1, len(result.inserted_ids))
        except Exception as e:
            logger.error("Erro ao inserir lote %d: %s", batch_idx + 1, e)
            # Fallback: inserir um por um
            for j, doc in enumerate(batch):
                if insert_document_fallback(doc, batch_idx, j):
                    inserted_count += 1

    logger.info("✅ Indexação finalizada: %d/%d páginas inseridas", inserted_count, pdf.page_count)
    pdf.close()
    
    # Remove o arquivo PDF temporário se foi criado a partir de upload
    if os.path.exists(pdf_path) and pdf_path.startswith('/tmp/') or pdf_path.startswith('./temp_'):
        try:
            os.remove(pdf_path)
            logger.info("🗑️ PDF temporário removido: %s", pdf_path)
        except Exception as e:
            logger.warning("⚠️ Erro ao remover PDF temporário: %s", e)

if __name__ == "__main__":
    asyncio.run(main())
