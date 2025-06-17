"""Tests for configuration system."""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, mock_open
import sys

# Add project root to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from config import EnvConfig, create_default_env_file, get_config, reload_config


class TestEnvConfig:
    """Test EnvConfig functionality."""
    
    def test_empty_initialization(self):
        """Test initialization with no env file."""
        with patch('config.Path.exists', return_value=False):
            config = EnvConfig()
            assert config.env_file_used is None
            assert len(config.env_vars) == 0
    
    def test_specific_env_file(self):
        """Test initialization with specific env file."""
        env_content = """
# Test environment file
OPENAI_API_KEY=test_openai_key
VOYAGE_API_KEY=test_voyage_key
ASTRA_DB_API_ENDPOINT=https://test-endpoint.apps.astra.datastax.com
ASTRA_DB_APPLICATION_TOKEN=AstraCS:test-token
COLLECTION_NAME=test_documents
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            config = EnvConfig(env_file=temp_path)
            
            assert config.env_file_used == str(Path(temp_path).absolute())
            assert config.get("OPENAI_API_KEY") == "test_openai_key"
            assert config.get("VOYAGE_API_KEY") == "test_voyage_key"
            assert config.get("ASTRA_DB_API_ENDPOINT") == "https://test-endpoint.apps.astra.datastax.com"
            assert config.get("ASTRA_DB_APPLICATION_TOKEN") == "AstraCS:test-token"
            assert config.get("COLLECTION_NAME") == "test_documents"
        finally:
            os.unlink(temp_path)
    
    def test_env_file_parsing(self):
        """Test parsing of various env file formats."""
        env_content = '''
# Comments should be ignored
SIMPLE_VAR=simple_value
QUOTED_VAR="quoted value"
SINGLE_QUOTED='single quoted'
EQUALS_IN_VALUE=key=value=with=equals
EMPTY_VAR=
# COMMENTED_VAR=should_not_appear

SPACES_AROUND = value with spaces 
'''
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            config = EnvConfig(env_file=temp_path)
            
            assert config.get("SIMPLE_VAR") == "simple_value"
            assert config.get("QUOTED_VAR") == "quoted value"
            assert config.get("SINGLE_QUOTED") == "single quoted"
            assert config.get("EQUALS_IN_VALUE") == "key=value=with=equals"
            assert config.get("EMPTY_VAR") == ""
            assert config.get("COMMENTED_VAR") is None
            assert config.get("SPACES_AROUND") == "value with spaces"
        finally:
            os.unlink(temp_path)
    
    def test_auto_find_env_current_directory(self):
        """Test auto-finding env file in current directory."""
        env_content = "TEST_VAR=current_dir_value"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text(env_content)
            
            with patch('config.Path.cwd', return_value=Path(temp_dir)):
                config = EnvConfig()
                
                assert config.env_file_used == str(env_path)
                assert config.get("TEST_VAR") == "current_dir_value"
    
    def test_auto_find_env_project_root(self):
        """Test auto-finding env file in project root."""
        env_content = "TEST_VAR=project_root_value"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text(env_content)
            
            # Mock Path(__file__).parent to return temp_dir
            with patch('config.Path.cwd', return_value=Path("/nonexistent")):
                with patch('config.Path.__file__', str(Path(temp_dir) / "config.py")):
                    with patch.object(Path, 'parent', Path(temp_dir)):
                        config = EnvConfig()
                        
                        assert config.get("TEST_VAR") == "project_root_value"
    
    def test_get_required_vars(self):
        """Test getting required variables."""
        env_content = """
OPENAI_API_KEY=test_openai
VOYAGE_API_KEY=test_voyage
ASTRA_DB_API_ENDPOINT=test_endpoint
# Missing ASTRA_DB_APPLICATION_TOKEN
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            config = EnvConfig(env_file=temp_path)
            required = config.get_required_vars()
            
            assert "OPENAI_API_KEY" in required
            assert "VOYAGE_API_KEY" in required
            assert "ASTRA_DB_API_ENDPOINT" in required
            assert len(required) == 3  # Missing ASTRA_DB_APPLICATION_TOKEN
        finally:
            os.unlink(temp_path)
    
    def test_get_missing_vars(self):
        """Test getting missing required variables."""
        env_content = """
OPENAI_API_KEY=test_openai
# Missing other required vars
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            config = EnvConfig(env_file=temp_path)
            missing = config.get_missing_vars()
            
            assert "VOYAGE_API_KEY" in missing
            assert "ASTRA_DB_API_ENDPOINT" in missing
            assert "ASTRA_DB_APPLICATION_TOKEN" in missing
            assert "OPENAI_API_KEY" not in missing
            assert len(missing) == 3
        finally:
            os.unlink(temp_path)
    
    def test_is_ready_complete(self):
        """Test is_ready with complete configuration."""
        env_content = """
OPENAI_API_KEY=test_openai
VOYAGE_API_KEY=test_voyage
ASTRA_DB_API_ENDPOINT=test_endpoint
ASTRA_DB_APPLICATION_TOKEN=test_token
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            config = EnvConfig(env_file=temp_path)
            assert config.is_ready() is True
        finally:
            os.unlink(temp_path)
    
    def test_is_ready_incomplete(self):
        """Test is_ready with incomplete configuration."""
        env_content = """
OPENAI_API_KEY=test_openai
# Missing other required vars
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            config = EnvConfig(env_file=temp_path)
            assert config.is_ready() is False
        finally:
            os.unlink(temp_path)
    
    def test_environment_variable_priority(self):
        """Test that environment variables take priority over file."""
        env_content = "TEST_VAR=file_value"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            # Set environment variable
            with patch.dict(os.environ, {'TEST_VAR': 'env_value'}):
                config = EnvConfig(env_file=temp_path)
                # Environment variable should take priority
                assert config.get("TEST_VAR") == "env_value"
        finally:
            os.unlink(temp_path)
    
    def test_default_value(self):
        """Test get method with default value."""
        config = EnvConfig()
        
        assert config.get("NONEXISTENT_VAR", "default_value") == "default_value"
        assert config.get("NONEXISTENT_VAR") is None
    
    def test_invalid_env_file(self):
        """Test handling of invalid env file path."""
        config = EnvConfig(env_file="/nonexistent/path/.env")
        
        assert config.env_file_used is None
        assert len(config.env_vars) == 0
    
    def test_print_status_complete(self, capsys):
        """Test print_status with complete configuration."""
        env_content = """
OPENAI_API_KEY=sk-test123456789
VOYAGE_API_KEY=pa-test123456789
ASTRA_DB_API_ENDPOINT=https://test.astra.datastax.com
ASTRA_DB_APPLICATION_TOKEN=AstraCS:test
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            config = EnvConfig(env_file=temp_path)
            config.print_status()
            
            captured = capsys.readouterr()
            assert "Environment Configuration Status" in captured.out
            assert "All required variables found!" in captured.out
            assert "OPENAI_API_KEY: sk-test12..." in captured.out
        finally:
            os.unlink(temp_path)
    
    def test_print_status_incomplete(self, capsys):
        """Test print_status with incomplete configuration."""
        env_content = "OPENAI_API_KEY=test_key"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            config = EnvConfig(env_file=temp_path)
            config.print_status()
            
            captured = capsys.readouterr()
            assert "Missing variables" in captured.out
            assert "VOYAGE_API_KEY" in captured.out
            assert "Setup options:" in captured.out
        finally:
            os.unlink(temp_path)


class TestCreateDefaultEnvFile:
    """Test create_default_env_file function."""
    
    def test_create_default_env_file(self):
        """Test creating default env file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            
            result_path = create_default_env_file(str(env_path))
            
            assert result_path == str(env_path)
            assert env_path.exists()
            
            content = env_path.read_text()
            assert "OPENAI_API_KEY=" in content
            assert "VOYAGE_API_KEY=" in content
            assert "ASTRA_DB_API_ENDPOINT=" in content
            assert "ASTRA_DB_APPLICATION_TOKEN=" in content
            assert "your-openai-api-key-here" in content
    
    def test_create_default_env_file_current_dir(self):
        """Test creating default env file in current directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('config.Path.cwd', return_value=Path(temp_dir)):
                result_path = create_default_env_file()
                
                expected_path = Path(temp_dir) / ".env"
                assert result_path == str(expected_path)
                assert expected_path.exists()
    
    def test_create_default_env_file_error(self):
        """Test handling error when creating env file."""
        # Try to create file in non-existent directory
        result_path = create_default_env_file("/nonexistent/directory/.env")
        
        assert result_path == ""


class TestGlobalFunctions:
    """Test global configuration functions."""
    
    def test_get_config(self):
        """Test get_config function."""
        config = get_config()
        assert isinstance(config, EnvConfig)
    
    def test_reload_config(self):
        """Test reload_config function."""
        env_content = "TEST_RELOAD=reload_value"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            new_config = reload_config(temp_path)
            assert isinstance(new_config, EnvConfig)
            assert new_config.get("TEST_RELOAD") == "reload_value"
            
            # Verify global config was updated
            global_config = get_config()
            assert global_config.get("TEST_RELOAD") == "reload_value"
        finally:
            os.unlink(temp_path)
    
    def test_reload_config_auto_discovery(self):
        """Test reload_config with auto-discovery."""
        new_config = reload_config()
        assert isinstance(new_config, EnvConfig)


class TestEnvironmentVariableIntegration:
    """Test integration with actual environment variables."""
    
    def test_os_environ_integration(self):
        """Test that config properly sets os.environ variables."""
        env_content = """
TEST_INTEGRATION=integration_value
ANOTHER_VAR=another_value
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            # Clear any existing values
            if "TEST_INTEGRATION" in os.environ:
                del os.environ["TEST_INTEGRATION"]
            if "ANOTHER_VAR" in os.environ:
                del os.environ["ANOTHER_VAR"]
            
            config = EnvConfig(env_file=temp_path)
            
            # Should be set in os.environ
            assert os.environ.get("TEST_INTEGRATION") == "integration_value"
            assert os.environ.get("ANOTHER_VAR") == "another_value"
            
            # Should also be accessible via config
            assert config.get("TEST_INTEGRATION") == "integration_value"
            assert config.get("ANOTHER_VAR") == "another_value"
        finally:
            # Cleanup
            if "TEST_INTEGRATION" in os.environ:
                del os.environ["TEST_INTEGRATION"]
            if "ANOTHER_VAR" in os.environ:
                del os.environ["ANOTHER_VAR"]
            os.unlink(temp_path)


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_malformed_env_lines(self):
        """Test handling of malformed env file lines."""
        env_content = """
VALID_VAR=valid_value
INVALID_LINE_NO_EQUALS
=NO_KEY_VALUE
KEY_WITH_NO_VALUE=
MULTIPLE===EQUALS=value
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            config = EnvConfig(env_file=temp_path)
            
            assert config.get("VALID_VAR") == "valid_value"
            assert config.get("INVALID_LINE_NO_EQUALS") is None
            assert config.get("NO_KEY_VALUE") is None
            assert config.get("KEY_WITH_NO_VALUE") == ""
            assert config.get("MULTIPLE") == "==EQUALS=value"
        finally:
            os.unlink(temp_path)
    
    def test_unicode_content(self):
        """Test handling of unicode content in env file."""
        env_content = """
UNICODE_VAR=Hello 世界 🌍
EMOJI_VAR=🔑 API Key 🚀
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False, encoding='utf-8') as f:
            f.write(env_content)
            temp_path = f.name
        
        try:
            config = EnvConfig(env_file=temp_path)
            
            assert config.get("UNICODE_VAR") == "Hello 世界 🌍"
            assert config.get("EMOJI_VAR") == "🔑 API Key 🚀"
        finally:
            os.unlink(temp_path)