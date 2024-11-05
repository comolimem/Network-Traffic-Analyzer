Project Overview
In this project, I developed a Python program that utilizes various libraries for packet capture and analysis, visualization, and a user-friendly GUI. The primary libraries used include Scapy for packet capture, PyShark for packet analysis, Pandas for data manipulation, and Matplotlib for data visualization. The GUI was designed using Figma, enhancing the user experience with a visually appealing layout.

Libraries Used
Scapy: For capturing network packets using the sniff() function.
PyShark: To analyze captured packets from the .pcap file.
Pandas: To create a structured DataFrame from captured data for easy manipulation and display.
Matplotlib: For visualizing the packet data in a table format.
Tkinter: To create the GUI interface, including input fields and buttons.
Psutil: To check the status of network interfaces.
Script Structure and Functionality
Initialization:
Import necessary libraries and initialize variables, including a list to store captured packets and predefined common ports and interfaces.
Utility Functions:
is_interface_active(interface): Checks if a specified network interface is active.
packet_callback(packet): A callback function that appends captured packets to the list.
is_valid_ip(ip): Validates the format of the user-provided IP address.
Main Capture Logic:
start_capture():
Validates user inputs (packet count, filters).
Captures packets using Scapy and saves them to a .pcap file.
Analyzes the captured packets using PyShark and filters them based on user criteria.
Creates a DataFrame and displays the results using Matplotlib.
GUI Functions:
display_table(df): Uses Matplotlib to create a visual table of the captured packet data.
show_filter_interface(): Sets up the filtering interface with input fields for packet capture parameters.
GUI Setup:
Initializes the Tkinter window, sets its title and size, and displays the initial background image designed in Figma.
A button to navigate to the filtering interface triggers the show_filter_interface() function.
GUI Design and Assets
The GUI was crafted using Figma, emphasizing user interaction and aesthetic appeal. Key assets include:

startbackground.png: Background for the initial screen.
filterbackground.png: Background for the packet filtering interface.
startpushbutton.png: Image for the start button, enhancing visual engagement.
Conclusion
This project effectively combines multiple libraries to create a robust tool for capturing and analyzing network packets, with a focus on user experience through an intuitive GUI. The use of Figma for design allows for a polished interface that is both functional and visually appealing.
