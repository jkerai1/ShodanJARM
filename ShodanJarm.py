import shodan
import sys
import json
import os
from dotenv import load_dotenv

load_dotenv("ShodanToken.env")
SHODAN_API_KEY = token = os.getenv("Token")
country="be"
network=""
hits = 0
api = shodan.Shodan(SHODAN_API_KEY)

try:
    f = open('jarm.txt','r')
    f_result = open('results.txt','w')
    f_output = open('output.txt', 'w')
    f_result.close()
    f_output.close()
    f_result = open('results.txt','a')
    f_output = open('output.txt', 'a')

    for jarm in f:
        jarm_strip = jarm.strip()
        results = api.search("ssl.jarm:{} country:{}".format(jarm_strip, country))
        print(results)
        f_result.write(json.dumps(results))
        f_result.write("\n")
        for result in results['matches']:
            hits += 1
            print("{} {} {} {} {}".format(jarm_strip, result['ip_str'], result['isp'], result['hostnames'], result['ssl']['cert']['subject']))
            f_output.write("{} {} {} {} {}\n".format(jarm_strip, result['ip_str'], result['isp'], result['hostnames'], result['ssl']['cert']['subject']))
        print("Hits: {}".format(hits)) 
    f_result.close()
    f_output.close()
except Exception as e:
        raise e
        
