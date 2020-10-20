# junkscripts

This is where I keep all the scripts that I wrote as helper functions that could be useful/generalised to other projects.

1. tcp_stream_extraction.py (Used to extract TCP streams in a pcap file and save it into its own pcap file)
      - Usage: ./tcp_stream_extraction.py <pcapfile>')
      - Example: ./tcp_stream_extraction.py /tmp/test.pcap')
      - Note: Can be adapted for UDP streams
  
2. ml_fwaf.py (Used to create a model to detect malicious web queries within internal traffic)
