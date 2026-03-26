def print_host_table(hosts):
    vendor_column_width = max(len(host['vendor']) for host in hosts) + 2
    hostname_column_width = max(len(host['hostname']) for host in hosts) + 2

    # Display table header
    print(f"{'Vendor':<{vendor_column_width}} {'Hostname':<{hostname_column_width}}")
    print(f"{'-' * vendor_column_width} {'-' * hostname_column_width}")

    # Display host entries
    for host in hosts:
        print(f"{host['vendor']:<{vendor_column_width}} {host['hostname']:<{hostname_column_width}}")

    print('\nScroll horizontally to view more entries in small terminals!\n")