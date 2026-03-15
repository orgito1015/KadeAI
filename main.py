#!/usr/bin/env python3
"""
KadeAI - AI-Powered Cybersecurity Agent
Entry point
"""

import asyncio
from kadeai.agent import KadeAgent
from kadeai.config import load_config
from kadeai.utils.logger import setup_logger

logger = setup_logger("kadeai.main")


async def main():
    print("""
  ██╗  ██╗ █████╗ ██████╗ ███████╗ █████╗ ██╗
  ██║ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║
  █████╔╝ ███████║██║  ██║█████╗  ███████║██║
  ██╔═██╗ ██╔══██║██║  ██║██╔══╝  ██╔══██║██║
  ██║  ██╗██║  ██║██████╔╝███████╗██║  ██║██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝
  AI-Powered Cybersecurity Agent v0.1.0
    """)

    config = load_config()
    agent = KadeAgent(config)

    print("KadeAI is ready. Type 'help' for commands or 'exit' to quit.\n")

    while True:
        try:
            user_input = input("kade> ").strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                print("Goodbye.")
                break
            if user_input.lower() == "help":
                agent.print_help()
                continue

            response = await agent.run(user_input)
            print(f"\n{response}\n")

        except KeyboardInterrupt:
            print("\nInterrupted. Type 'exit' to quit.")
        except Exception as e:
            logger.error(f"Error: {e}")
            print(f"[error] {e}")


if __name__ == "__main__":
    asyncio.run(main())
