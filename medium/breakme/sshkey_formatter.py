import argparse

def format_openssh_private_key(key_str: str) -> str:
    """
    Clean and format an OpenSSH private key string to proper line length (64 chars per line).
    Keeps the header/footer intact and reformats the base64 data.
    """
    lines = key_str.strip().splitlines()

    # Find header and footer indices
    try:
        start_idx = lines.index("-----BEGIN OPENSSH PRIVATE KEY-----")
        end_idx = lines.index("-----END OPENSSH PRIVATE KEY-----")
    except ValueError:
        raise ValueError("Key does not contain proper BEGIN/END headers")

    header = lines[start_idx]
    footer = lines[end_idx]

    # Extract all base64 lines between header and footer and join into one string (remove spaces)
    base64_data = "".join(line.strip() for line in lines[start_idx + 1 : end_idx])
    base64_data = base64_data.replace(" ", "").replace("\t", "")

    # Re-split base64_data into lines of length 64
    formatted_base64_lines = [
        base64_data[i : i + 64] for i in range(0, len(base64_data), 64)
    ]

    # Combine all parts
    formatted_key = "\n".join([header] + formatted_base64_lines + [footer]) + "\n"
    return formatted_key


def main():
    parser = argparse.ArgumentParser(description="Format and clean OpenSSH private key files.")
    parser.add_argument(
        "input_file",
        help="Path to the input OpenSSH private key file (can be unformatted).",
    )
    parser.add_argument(
        "output_file",
        help="Path to save the cleaned and formatted private key file.",
    )

    args = parser.parse_args()

    with open(args.input_file, "r") as f:
        key_text = f.read()

    try:
        formatted_key = format_openssh_private_key(key_text)
        with open(args.output_file, "w") as f_out:
            f_out.write(formatted_key)
        print(f"Formatted key saved to {args.output_file}")
    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    main()
