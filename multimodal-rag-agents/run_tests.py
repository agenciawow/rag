#!/usr/bin/env python3
"""Test runner script for multimodal RAG agents."""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description):
    """Run a command and report results."""
    print(f"\n{'='*60}")
    print(f"🧪 {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=Path(__file__).parent)
        
        if result.returncode == 0:
            print(f"✅ {description} - PASSED")
            if result.stdout:
                print(result.stdout)
        else:
            print(f"❌ {description} - FAILED")
            if result.stderr:
                print("STDERR:", result.stderr)
            if result.stdout:
                print("STDOUT:", result.stdout)
            return False
            
    except Exception as e:
        print(f"❌ {description} - ERROR: {e}")
        return False
    
    return True

def install_test_dependencies():
    """Install test dependencies."""
    print("📦 Installing test dependencies...")
    return run_command("pip install -e .[test]", "Installing test dependencies")

def run_unit_tests():
    """Run unit tests."""
    return run_command("python -m pytest tests/unit/ -v -m 'not slow'", "Running unit tests")

def run_integration_tests():
    """Run integration tests."""
    return run_command("python -m pytest tests/integration/ -v -m 'not slow'", "Running integration tests")tidef run_all_tests():
    """Run all tests."""
    return run_command("python -m pytest tests/ -v", "Running all tests")

def run_tests_with_coverage():
    """Run tests with coverage report."""
    return run_command("python -m pytest tests/ --cov=src --cov-report=html --cov-report=term", "Running tests with coverage")

def run_linting():
    """Run code linting."""
    success = True
    
    # Check if ruff is available
    try:
        subprocess.run(["ruff", "--version"], capture_output=True, check=True)
        success &= run_command("ruff check src/", "Running ruff linter")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  Ruff not available, skipping linting")
    
    return success
    
    def main():
    """Main test runner."""
    print("🚀 Multimodal RAG Agents - Test Suite")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not Path("src/rag_agents").exists():
        print("❌ Error: Please run this script from the multimodal-rag-agents directory")
        sys.exit(1)
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        test_type = sys.argv[1].lower()
    else:
        test_type = "all"
    
    success = True
    
    # Install dependencies first
    if not install_test_dependencies():
        print("❌ Failed to install test dependencies")
        sys.exit(1)
    
    # Run tests based on argument
    if test_type == "unit":
        success = run_unit_tests()
    elif test_type == "integration":
        success = run_integration_tests()
    elif test_type == "coverage":
        success = run_tests_with_coverage()
    elif test_type == "lint":
        success = run_linting()
    elif test_type == "all":
        success &= run_linting()
        success &= run_unit_tests()
        success &= run_integration_tests()
    elif test_type == "quick":
        success &= run_unit_tests()
    else:
        print(f"❌ Unknown test type: {test_type}")
        print("Available options: unit, integration, coverage, lint, all, quick")
        sys.exit(1)
    
    # Final summary
    print(f"\n{'='*60}")
    if success:
        print("🎉 All tests completed successfully!")
        print("💡 System is ready for deployment")
    else:
        print("❌ Some tests failed")
        print("🔧 Please review the errors above and fix issues")
    print(f"{'='*60}\n")
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()eady for # Final summary
    print(f"\n{'='*60}")
    if success:
        print("🎉 All tests completed successfully!")
        print("💡 System is ready for deployment")
    else:
        print("❌ Some tests failed")
        print("🔧 Please review the errors above and fix issues")
    print(f"{'='*60}\n")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()