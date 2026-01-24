from urllib.parse import urlparse


def normalize_input(input_type: str, input_value: str) -> dict:
    """
    Normalizes and validates input before scanning
    """

    if input_type == "url":
        if not input_value.startswith(("http://", "https://")):
            input_value = "http://" + input_value

        parsed = urlparse(input_value)

        return {
            "type": "url",
            "url": input_value,
            "domain": parsed.hostname
        }

    return {
        "type": "text",
        "content": input_value
    }
