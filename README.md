# IP Calculator Tool

The IP Calculator is a command-line tool written in Golang that assists in managing IPv4 addresses, subnetting, IPv6 shortening, and various networking operations.

NOTE: This tool is a work in progress. Some features may not be working or non-existent.

## Features

- **IPv4 Operations:**
  - Calculate network details such as network address, broadcast address, and available hosts within a subnet.
  - Validate IPv4 addresses.
  - Perform subnetting calculations.
  - Perform route summarization calculations.
  
- **IPv6 Operations:**
  - Shorten IPv6 addresses using the compressed representation.
  - Extract and display IPv6 information like network prefix, interface ID, etc.

## Installation

Make sure you have Go installed. Clone the repository and build the tool:

```bash
git clone https://github.com/iLaurian/ip-calculator.git
cd ip-calculator
go build
```

## Usage

Run the ip-calculator executable with appropriate command-line arguments to utilize different functionalities:

### Example

IPv4 Information
```bash
./ip-calculator -ipv4 192.168.0.0/24 --info
```

IPv4 Route Summarization
```bash
./ip-calculator --summary-route 10.0.0.0,10.0.0.1,10.0.0.2,10.0.0.3
```

IPv4 VLSM Subnetting
```bash
./ip-calculator --ipv4=10.10.0.0/16 --vlsm 10,20,30,40
```
__NOTE__: The number of hosts should not include the broadcast and the network address. 

## Contributing

Contributions are welcome! If you find any bugs, have suggestions for improvements, or wish to add new features, feel free to open an issue or create a pull request.

Before making significant changes, please discuss them in an issue to ensure they align with the project's goals.