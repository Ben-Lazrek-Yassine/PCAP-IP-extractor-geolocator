from scapy.all import *
import requests
import csv
import ipaddress
import folium

class colors:
	HEADER = '\033[95m'
	BLUE = '\033[94m'
	CYAN = '\033[96m'
	GREEN = '\033[92m'
	REDUCE = '\033[93m'
	YELLOW = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	RED='\033[31m'

pcap_path=r'C:\Users\Yassine\Desktop\capture.pcapng'


def Extract_IPS(pcap_path):
	data=set((p['IP'].src, p['IP'].dst) for p in PcapReader(pcap_path) if 'IP' in p)
	Src_IPS=set(i[0] for i in data)
	return list(Src_IPS)

def Filter_IPS(ips):
	Filtered_Source=[]
	for i in ips:
		if ipaddress.ip_address(i).is_global and i != '8.8.8.8':
			Filtered_Source.append(i)
	if len(Filtered_Source) <1:
		exit(colors.RED + "[-] No ip to scan. ")
	return Filtered_Source

IP_list=Extract_IPS(pcap_path)
Filtered_Source=Filter_IPS(IP_list)

def get_ip_info(Filtered_Source):
	data = []
	for ip in Filtered_Source	:
		print(colors.YELLOW + "[+] Start analyzing IP : " + ip )
		try:
			req = requests.get("http://ip-api.com/json/"+ip+"?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,,query").content.decode()
			if "message" not in req:
				data.append(req)
		except requests.exceptions.ConnectionError:
			exit(colors.RED + "Check your internet connection and try again ....")
	dic_data = []
	for i in data:
		l = eval(i)
		dic_data.append(l)
	return dic_data

output_api=get_ip_info(Filtered_Source)

def export_csv(data):
	with open('ip_info.csv', 'w') as csvfile:
		fieldnames = ['status', 'message', 'country', 'countryCode', 'region', 'regionName', 'city', 'zip', 'lat', 'lon', 'timezone', 'isp', 'org', 'query']
		writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
		writer.writeheader()
		for i in data:
			writer.writerow(i)
	print("CSV exported successfully!")

def plot_map(data):
	m = folium.Map(location=[0,0],zoom_start=4)
	lat=[]
	lon=[]
	tooltip = "Click me!"
	for i in data:
		lat.append(i['lat'])
		lon.append(i['lon'])
	for i in range(len(lat)):
		folium.Marker([lat[i], lon[i]], popup=tooltip).add_to(m)
	m.save("map.html")
	print("Map exported successfully!")	


export_csv(output_api)
plot_map(output_api)
print(colors.GREEN + "[+] Done")
