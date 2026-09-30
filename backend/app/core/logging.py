import logging
import os


def setup() -> None:
    logging.basicConfig(level=os.environ.get("ACRS_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
