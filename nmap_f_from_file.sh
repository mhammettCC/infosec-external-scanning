#!/bin/bash

# Ensure exactly two arguments (the file with IP addresses and the output directory) are provided
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <ips_file> <output_directory>"
  exit 1
fi

# Input file containing the list of IP addresses
IPS_FILE="$1"

# Output directory to store results
OUTPUT_DIR="$2"

# Check if the file exists
if [ ! -f "$IPS_FILE" ]; then
  echo "File not found: $IPS_FILE"
  exit 1
fi

# Check if the directory exists, if not create it
if [ ! -d "$OUTPUT_DIR" ]; then
  echo "Output directory not found, creating: $OUTPUT_DIR"
  mkdir -p "$OUTPUT_DIR"
fi

# Derive the output file name by appending "_results.txt" to the input file name without extension
OUTPUT_FILE="${OUTPUT_DIR}/$(basename "$IPS_FILE" .txt)_results"

# Empty the output file if it exists
> "$OUTPUT_FILE"

# Count the total number of valid IP addresses (non-empty, non-comment lines)
TOTAL_COUNT=$(grep -vE '^\s*$|^\s*#' "$IPS_FILE" | wc -l)

# Initialize the current count
CURRENT_COUNT=0

# Loop through each IP address in the file
while IFS= read -r line; do
  ip=$(echo "$line" | xargs)  # Remove leading/trailing whitespace

  # Skip empty lines and lines starting with #
  if [[ -n "$ip" && ! "$ip" =~ ^# ]]; then
    # Increment the current count
    CURRENT_COUNT=$((CURRENT_COUNT + 1))

    # Display progress
    echo "Progress: $CURRENT_COUNT/$TOTAL_COUNT"
    echo "Scanning $ip..."

    # Run nmap with -F option
    echo "Results from: $ip" >> "$OUTPUT_FILE"
    nmap -F "$ip" | grep -E 'open' >> "$OUTPUT_FILE"

    # Check if nmap found any open ports
    if [ $? -ne 0 ]; then
      echo "Error scanning $ip - Most likely no open ports were detected"
    fi

    # Optional: Add a separator for clarity
    echo "---------------------------------" >> "$OUTPUT_FILE"
  fi
done < "$IPS_FILE"

echo "Scanning complete. Results saved to $OUTPUT_FILE."
