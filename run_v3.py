#!/usr/bin/env python3
"""
Wrapper script to properly run the Advanced Assistant V3
This ensures all modules are properly imported and configured
"""

import os
import sys
import subprocess

# Add src directory to Python path
src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
sys.path.insert(0, src_dir)

# Set up environment
def setup_environment():
    """Ensure environment is properly configured"""
    
    # Check for .env file
    if os.path.exists('.env'):
        print("📋 Loading environment variables from .env")
        from dotenv import load_dotenv
        load_dotenv()
    
    # Verify OpenAI API key
    if not os.getenv('OPENAI_API_KEY'):
        print("❌ OPENAI_API_KEY not set!")
        print("Please set it in .env file or export OPENAI_API_KEY=your_key")
        sys.exit(1)
    
    # Ensure required directories exist
    os.makedirs(os.path.expanduser("~/.bb_assistant"), exist_ok=True)
    
    print("✅ Environment configured")

def check_dependencies():
    """Check if all required tools are installed"""
    required_tools = {
        'subfinder': 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
        'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
        'nuclei': 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
        'gau': 'github.com/lc/gau/v2/cmd/gau@latest',
        'katana': 'github.com/projectdiscovery/katana/cmd/katana@latest'
    }
    
    missing_tools = []
    for tool, install_path in required_tools.items():
        if subprocess.run(['which', tool], capture_output=True).returncode != 0:
            missing_tools.append((tool, install_path))
    
    if missing_tools:
        print("⚠️  Missing tools detected. Installing...")
        for tool, install_path in missing_tools:
            print(f"📦 Installing {tool}...")
            subprocess.run(['go', 'install', '-v', install_path])
    
    print("✅ All tools available")

def main():
    """Run the advanced assistant v3"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║         Enhanced Bug Bounty Assistant v3.0                   ║
║         With Revenue Maximization & Monitoring               ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Setup
    setup_environment()
    check_dependencies()
    
    # Import and run v3
    try:
        from advanced_assistant_v3 import main as v3_main
        print("\n🚀 Starting Advanced Assistant v3.0...\n")
        v3_main()
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure advanced_assistant_v3.py is in the src/ directory")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
