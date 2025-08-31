#!/usr/bin/env python3
"""
Test runner script for the MCP OAuth client tests
"""
import subprocess
import sys
import os


def run_tests():
    """Run the test suite with coverage reporting"""
    print("🧪 Running MCP OAuth Client Tests")
    print("=" * 50)

    # Install test dependencies if needed
    print("📦 Installing test dependencies...")
    subprocess.run(["uv", "sync", "--extra", "test"], check=True)

    # Run tests with coverage
    print("\n🧪 Running tests with coverage...")
    cmd = [
        "uv",
        "run",
        "pytest",
        "test_client.py",
        "-v",
        "--cov=client",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov",
        "--tb=short",
    ]

    result = subprocess.run(cmd)

    if result.returncode == 0:
        print("\n✅ All tests passed!")
        print("\n📊 Coverage report generated:")
        print("  - Terminal: shown above")
        print("  - HTML: htmlcov/index.html")

        # Try to open coverage report in browser
        if os.path.exists("htmlcov/index.html"):
            print("\nTo view detailed coverage report, open: htmlcov/index.html")
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)


def run_specific_test(test_name):
    """Run a specific test"""
    cmd = ["uv", "run", "pytest", f"test_client.py::{test_name}", "-v"]
    subprocess.run(cmd)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Run specific test
        run_specific_test(sys.argv[1])
    else:
        # Run all tests
        run_tests()
