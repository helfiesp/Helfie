import ast
import time
import requests
from bs4 import BeautifulSoup as bs
from datetime import datetime, timedelta
from datetime import date
from collections import defaultdict
import sys
import argparse
from cvsslib import cvss2, cvss3, calculate_vector

class CVEScanner:
    """
    This program scans for CVEs both using the NIST API and the NIST webpage.
    The results are filtered and placed into HTML tables.
    """
    def __init__(self):
        print("<{}> OKCSIRT CVE Scanner <{}>".format("-"*15, "-"*15))
        self.main()

    def main(self):
        """
        This function is used when the program is called with command line arguments.
        """
        parser = argparse.ArgumentParser(description='CVE Scanner\nOslo kommune CSIRT',formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("-w", "--weekly", help="CVEs from the last 7 days.", action="store_true")
        parser.add_argument("-d", "--daily", help="Yesterdays CVEs.", action="store_true")
        parser.add_argument("-m", "--mod", help="Newly modified CVEs", action="store_true")
        parser.add_argument("-f", "--full", help="Both newly published CVEs and modified CVEs.", action="store_true")
        parser.add_argument("-n", "--news", help="Run news scanner", action="store_true")
        parser.add_argument("-kw", "--keyword", help="Search via a specific keyword. Syntax: -kw log4j")
        parser.add_argument("-s", "--single", help="Search for a single CVE: YYYY-ID")
        parser.add_argument("-dr", "--date-range", help="Search in a date range: YYYY-MM-DD YYYY-MM-DD", nargs=2)
        parser.add_argument("-md", "--mod-data", help="Full CPE modification data or not, default none", action="store_true")
        if len(sys.argv) == 1:
            sys.argv.append('-h')
        if datetime.today().weekday() == 4:
            print("[!] It is Friday, running weekly scan...")
            sys.argv.append('-w')
        args = parser.parse_args()
        arguments = vars(args)
        self.user_input = arguments
        self.main_params(arguments)

    def main_params(self, arguments):
        """
        This function handles all of the parameters given to the program, and calls the correct functions.
        """
        if arguments["daily"] and arguments["weekly"]:
            print("[!] Friday weekly...")
            self.full_cve_scan(1)
        elif arguments["daily"]:
            if arguments["full"]:
                self.full_cve_scan()
            elif arguments["mod"]:
                self.daily_cve("mod")
            else:
                self.daily_cve("pub")
        elif arguments["weekly"]:
            if arguments["full"]:
                self.full_cve_scan()
            elif arguments["mod"]:
                self.last_week_cve("mod")
            else:
                self.last_week_cve("pub")
        else:
            if arguments["keyword"]:
                self.defined_search("keyword", arguments["keyword"])
            elif arguments["single"]:
                self.cve_search_single(arguments["single"])
            elif arguments["date_range"]:
                print(arguments["date_range"][0], arguments["date_range"][1])
                if arguments["mod"]:
                    self.date_range_search("mod", arguments["date_range"][0], arguments["date_range"][1])
                else:
                    self.date_range_search("pub", arguments["date_range"][0], arguments["date_range"][1])
            elif arguments["full"]:
                print("You have to choose either daily (-d) og weekly (-w)")

    def full_cve_scan(self, weekcheck=None):
        """
        This function is called if the user wants both newly published and modified CVEs.
        """
        print("[!] Running scan for new and modified CVEs")
        self.full_html_files = []
        if self.user_input["daily"]:
            self.daily_cve("pub")
            if not weekcheck:
                self.daily_cve("mod")
        if self.user_input["weekly"]:
            self.last_week_cve("pub")
            if not weekcheck:
                self.last_week_cve("mod")

    def last_week_cve(self, parameter):
        """
        This function fetches all of the CVEs from the previous week.
        """
        self.current_parameter = parameter
        self.current_scan_type = "Weekly"
        days_list = []
        for x in range(7):
            day = date.today() - timedelta(days=x + 1)
            days_list.append(day.strftime("%Y-%m-%d"))
        print("[!] Gathering the CVEs between: {} and {}".format(days_list[-1], days_list[0]))
        self.date_range_search(parameter, days_list[-1], days_list[0])

    def daily_cve(self, parameter):
        """
        This function fetches all of the CVEs that was added to NVD for the previous calendar day.
        """
        print("[*] Running daily CVE scan with parameter: {}".format(parameter))
        self.current_scan_type = "Daily"
        self.current_parameter = parameter
        yesterday = datetime.strftime(datetime.today() - timedelta(1), "%Y-%m-%d")
        self.date_range_search(parameter, yesterday, yesterday, userinput=yesterday)

    def cve_search_single(self, cve):
        """
        Finds all of the data connected to a single CVE.
        Usage: self.cve_search_single("CVE-2021-44228")
        """
        self.current_scan_type = "Single"
        cve = "CVE-{}".format(cve)
        url = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
        cve_data = requests.get('{}{}'.format(url, cve)).json()["result"]["CVE_Items"]
        self.cve_data_handler(cve_data, userinput=cve)

    def date_range_search(self, type=None, date1=None, date2=None, base_url=None, userinput=None):
        """
        Retrieves all of the CVEs within a specific date window.
        Parameter1 is specified to be either mod or pub, referencing modified or published.
        The NVD API only fetches 20 results at a time, so a while statement was made to ensure all data was obtained (cve_page_processor).
        """
        if not base_url:
            base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0/?{}StartDate={}T00:00:00:000 UTC-00:00&{}EndDate={}T23:59:00:000 UTC-00:00".format(type, date1, type, date2)
        result = requests.get(base_url).json()
        user_input = [userinput, type]
        cve_data = result["result"]["CVE_Items"]
        self.cve_page_processor(result["totalResults"], result["resultsPerPage"], base_url, result["result"]["CVE_Items"])
        self.cve_data_handler(cve_data, user_input)

    def cve_page_processor(self, result_amount, results_per_page, base_url, cve_data):
        """
        Processes all of the CVE pages of CVEs and appends them to the list.
        """
        while result_amount != results_per_page:
            print("[!] Adding all CVEs to list: {} of {}...".format(results_per_page, result_amount), end='\r')
            url = "{}&startIndex={}".format(base_url, results_per_page)
            results_per_page += requests.get(url).json()["resultsPerPage"]
            cve_data.extend(requests.get(url).json()["result"]["CVE_Items"])
            time.sleep(0.2)

    def cve_data_handler(self, cve_data, userinput=None):
        """
        This function is the main data handler for the CVE data.
        The method is used by all CVE request functions, and calls the HTML creator functions.
        """
        cve_data_dict = {}
        all_data = []
        found_changes = ""
        print("[!] CVE checker started...")
        print("[!] Checking {} CVEs...\n".format(len(cve_data)))
        for cve in cve_data:
            cve_base_info = cve["cve"]
            cve_config = cve["configurations"]
            cve_mod_date = cve["lastModifiedDate"].split("T")[0]
            cve_pub_date = cve["publishedDate"].split("T")[0]
            cve_url = cve["cve"]["CVE_data_meta"]["ID"]
            print("[*] Checking CVE: {}...".format(cve_url))
            cve_source = cve["cve"]["CVE_data_meta"]["ASSIGNER"]
            cve_description = cve_base_info["description"]["description_data"][0]["value"].replace("<", '"').replace(
                ">", '"')
            affected_systems = self.get_affected_systems(cve_config["nodes"])
            if str(affected_systems) == "('', [], [])":
                affected_systems = ""
                check_impact = self.check_impact(cve_description)
            else:
                if len(affected_systems[0]) > 500:
                    affected_systems = "<b>Affected suppliers:</b> {}<br>Read more on the CVE page.".format(
                        ", ".join(affected_systems[1]), cve_url)
                    check_impact = self.check_impact(cve_description, affected_systems[2])
                else:
                    affected_systems = affected_systems[0]
                    check_impact = self.check_impact(cve_description, affected_systems[2])

            if len(cve["impact"]) != 0:
                try:
                    cve_base_score = cve["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                except:
                    cve_base_score = cve["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                if userinput[1] == "mod":
                    found_changes = self.fetch_cve_changes(cve_url)
            else:
                if userinput[1] == "mod":
                    valuechecker = self.check_cvss_score(cve_url, "mod")
                    found_changes = valuechecker[2]
                else:
                    valuechecker = self.check_cvss_score(cve_url)
                cve_base_score = valuechecker[0]
                cve_source = valuechecker[1]
            cve_data_dict["CVE"] = cve_url
            cve_data_dict["Date added"] = cve_pub_date
            if "mod" in userinput:
                if found_changes == "No changes found." or len(found_changes) <= 1:
                    continue
                cve_data_dict["Date modified"] = cve_mod_date
                cve_data_dict["Source"] = cve_source
                cve_data_dict["CVSS score"] = cve_base_score
                cve_data_dict["Affected systems"] = affected_systems
                cve_data_dict["Potentially impacted"] = check_impact
                cve_data_dict["Changes"] = found_changes
                cve_data_dict["CVE Description"] = cve_description
            else:
                cve_data_dict["Source"] = cve_source
                cve_data_dict["CVSS score"] = cve_base_score
                cve_data_dict["Affected systems"] = affected_systems
                cve_data_dict["Potentially impacted"] = check_impact
                cve_data_dict["CVE Description"] = cve_description
            all_data.append(cve_data_dict.copy())
        self.write_html(all_data)

    def check_impact(self, description, configurations=None):
        """
        This function is used to check the CVE up against specific keywords.
        The result will be a True or False statement if potentially impacted
        """
        with open('cve_tracker_keywords.txt') as f:
            known_keywords = f.read().splitlines()
        found_keywords = []

        def check_keyword(input):
            for keyword in known_keywords:
                if keyword.lower() in input.lower():
                    if ' ' in keyword:
                        found_keywords.append(keyword)
                        continue
                    elif keyword.lower() in input.lower().split():
                        found_keywords.append(keyword)
                        continue
                    else:
                        if keyword.lower() in input.lower().replace("(", "").replace(")", "").split():
                            found_keywords.append("{}".format(keyword))
                            continue
        check_keyword(description)
        if configurations:
            for entry in configurations:
                check_keyword(entry)
        found_keywords = ", ".join(self.clear_duplicates(found_keywords))
        return found_keywords

    def defined_search(self, parameter, value):
        """
        Retrieves a collection CVEs with own parameter and values
        Example: self.defined_search("keyword", "log4j")
        """
        self.current_scan_type = "Keyword"
        url = "https://services.nvd.nist.gov/rest/json/cves/1.0?{}={}".format(parameter, value)
        result = requests.get(url).json()
        cve_data = result["result"]["CVE_Items"]
        userinput = "{}_{}".format(parameter, value)
        check = self.cve_page_processor(result["totalResults"], result["resultsPerPage"], url, cve_data)
        if check:
            self.cve_data_handler(result, userinput)
        else:
            self.cve_data_handler(cve_data, userinput)

    def write_html(self, all_data):
        """
        This function is meant to transform all of the CVE data into HTML code.
        The function needs some cleaning up and optimization, as there are repeating lines of code with slight changes.
        """
        cve_statistics = self.cve_statistics(all_data)
        base_html = self.base_html_init(all_data, cve_statistics)
        full_dict = {}
        full_data = []
        centering = 'style="text-align:center;"'
        for cve in all_data:
            working_html = "<tr>"
            for key, value in cve.items():
                if key == "CVSS score":
                    if value == "n/a":
                        cve["CVSS score"] = 0
                        working_html += """<td {} bgcolor="#bfbfbf";>{}</td>""".format(centering, value)
                    else:
                        value = float(value)
                        if value <= 5:
                            working_html += """<td {} bgcolor="#99ff99";><b>{}</b></td>""".format(centering, value)
                        elif value <= float(7.4):
                            working_html += """<td {} bgcolor="#ebcc34";><b>{}</b></td>""".format(centering, value)
                        elif value >= float(7.5):
                            if value >= 9:
                                working_html += """<td {} bgcolor="#d41b00";><b>{}</b></td>""".format(centering, value)
                            else:
                                working_html += """<td {} bgcolor="#ed5f4a";><b>{}</b></td>""".format(centering, value)
                else:
                    if key == "CVE":
                        working_html += '<td {}><a href="https://nvd.nist.gov/vuln/detail/{}">{}</a></td>'.format(centering, value,value)
                    else:
                        working_html += "<td>{}</td>".format(value)
            keywords = 0
            working_html += "</tr>"
            full_dict["CVE"] = cve["CVE"]
            full_dict["HTML"] = working_html
            full_dict["SCORE"] = cve["CVSS score"]
            full_dict["KEYWORDS"] = keywords
            full_data.append(full_dict.copy())
        full_html = self.html_sorter(full_data, base_html)
        full_html += "</table></body></html>"
        user_input = ""
        for key, value in self.user_input.items():
            if value != False and value != None:
                if value == True:
                    user_input += key
                else:
                    user_input += "{}_{}".format(key, value)
        if not self.user_input["full"]:
            html_file_name = "cve_scan_{}_{}.html".format(user_input, date.today().strftime("%d_%m_%Y"))
            self.write_to_file(html_file_name, full_html, "w")
        else:
            html_file_name = "cve_scan_{}_{}_{}.html".format(self.current_parameter, user_input, date.today().strftime("%d_%m_%Y"))
            self.write_to_file(html_file_name, full_html, "w")
            self.full_html_files.append(html_file_name)


    def base_html_init(self, all_data, statistics):
        """
        This function is used to create the base HTML code for the CVE table layout.
        More might be added in the future for design and or other features.
        The HTML Code should not be written directly into the python code, but cba...
        """
        print("[!] Writing base html...")
        check = False
        for entry in all_data:
            if entry["Affected systems"]:
                check = True
        if check == False:
            for entry in all_data: entry.pop('Affected systems', None)
        all_data = self.check_dates(all_data)
        headers = all_data[0].keys()
        added_text = ""
        for key, value in self.user_input.items():
            if value != False and value != None:
                if value == True: added_text += "{} ".format(key)
                else: added_text += "{}: {}".format(key, value)
        html_code = "<!DOCTYPE html><html> <head> <title>OK CSIRT Alerts</title> <style> * { font-family: Arial } th { font-weight: bold; color: black; border: 1px solid black; border-collapse: collapse; padding:10px; } td { border: 1px solid black; border-collapse: collapse; padding:10px;} table { border: 1px solid black; border-collapse: collapse; font-family: Arial;} </style> </head><body>"
        top_header = '<h2 style="font-family: Arial">{} CVE Liste {}</h2>'.format(self.current_scan_type, datetime.strftime(datetime.today(), '%m/%d/%Y'))
        attachments = "Vedlegg: Vedlagt er en HTML versjon av denne filen, for å åpne i nettleser."
        header_text = """{}<p style="font-family: Arial">
        Vedlagt i listen ligger det CVEer fra spørring: {}<br><br>
        CVE Listen viser nylige utgitte CVEer, rangert etter CVSS score.<br>
        I potentially impacted vil det filtreres ut basert på systemer som OK benytter.<br>
        Denne listen oppdateres manuelt, og vil trolig mangle noen systemer, så det anbefales å skumlese alle CVEer.<br><br>{}""".format(top_header, added_text, attachments)
        top_paragraph = """<hr><p style="font-family: Arial"><b>CVE Statistikk</b><br>Totalt: {} Kritisk: {} Høy: {}, Medium: {}, Lav: {}, Ikke tilordnet: {}</p><br>""".format(
            statistics['total'], statistics['critical'], statistics['high'], statistics['medium'], statistics['low'],
            statistics['unassigned'])
        html_code += '{}<br><br>'.format(header_text)
        html_code += "{}<table>".format(top_paragraph)
        for header in headers: html_code += '<th bgcolor="#3399ff";>{}</th>'.format(header)
        return html_code

    def html_sorter(self, data, base_html):
        """
        This function takes the raw CVE data and sorts it by CVSS score.
        In the future this might also include other areas of sorting, for example sorted by if a keyword is present.
        """
        print("[!] Sorting HTML code...")
        sorted_list = sorted(data, key=lambda d: float(d['SCORE']), reverse=True)
        for entry in sorted_list:
            if entry["SCORE"] == 0: entry["SCORE"] = "n/a"
        for entry in sorted_list: base_html += entry["HTML"]
        return base_html

    def cve_statistics(self, data):
        """
        This function writes the statistics for the CVEs found.
        """
        statistics = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "unassigned": 0}
        for cve in data:
            score = cve["CVSS score"]
            statistics["total"] += 1
            if score == "n/a": statistics["unassigned"] += 1
            elif float(score) >= 9: statistics["critical"] += 1
            elif float(score) >= float(7.5) <= 8.9: statistics["high"] += 1
            elif float(score) >= 5 <= 7.4: statistics["medium"] += 1
            elif float(score) <= float(4.9): statistics["low"] += 1
        return statistics

    def check_dates(self, cve_data):
        """
        This function checks if all of the dates in the result are the same.
        If they are all the same, the date field is removed in the final HTML table.
        """
        result = True
        valuelist = [cve_dict["Date added"] for cve_dict in cve_data]
        first_element = valuelist[0]
        for entry in valuelist:
            if entry != first_element:
                result = False
                break
            else:
                result = True
        if result:
            for entry in cve_data:
                del entry["Date added"]
        return cve_data

    def check_cvss_score(self, url, changes=None):
        """
        The NVD API does not return a CVSS score if it has not been assigned by NVD itself.
        New vulnerabilities will not have a CVSS score assigned by NVD, but often by a third party.
        This function uses web scraping to fetch that CVSS score, and the source it comes from.
        """
        response = requests.get("https://nvd.nist.gov/vuln/detail/{}".format(url))
        html = response.content
        soup = bs(html, "lxml")
        sources = soup.find_all('span', {'class': 'wrapData'})
        if len(sources) == 1:
            cve_source = str(sources).split('">')[1][:-8]
        elif len(sources) >= 2:
            for source in sources:
                cve_source = str(source).split('">')[1][:-7]
        else:
            cve_source = "n/a"
        try:
            cvss_values = str(soup.find_all('a', {'id': 'Cvss3CnaCalculatorAnchor'})).split(">")[1].split("<")[
                0].split()
            cve_base_score = cvss_values[0]
        except:
            cve_base_score = "n/a"
        time.sleep(0.5)
        if changes:
            return cve_base_score, cve_source, self.fetch_cve_changes(url)
        else:
            return cve_base_score, cve_source

    def calculate_cvss_score(self, string):
        """
        This function calculates the CVSS score from the CVSS vector.
        The vector is received from when a change is made to a CVE CVSS score.
        """
        if len(string) > 30:
            result = calculate_vector(string, cvss3)[0]
        else:
            result = calculate_vector(string, cvss2)[0]
        return result

    def write_to_file(self, file, text, type):
        """
        The function takes a file parameter(file.txt) and a text value to write to a file.
        The function can also choose to overwrite or append(w, a)
        """
        f = open("{}".format(file), "{}".format(type))
        f.write(text)
        print("[!] Contents have been written to file: {}".format(file))
        f.close()

    def combine_lists_of_dict(self, list_of_dicts):
        """
        This function combines a list of dictonaries where the key is similar.
        """
        dd = defaultdict(list)
        for d in list_of_dicts:
            for key, value in d.items():
                dd[key].append(value)
        return dd

    def get_affected_systems(self, cve_config):
        """
        This method fetches the CPE Configurations field in the CVE page.
        This is the section where a system is added to show that the system is affected by the vulnerability.
        This field can be seen as known software configurations, or configurations.
        """
        systems = []
        total_systems = []
        for entry in cve_config:
            for item in entry["cpe_match"]:
                if item["vulnerable"]:
                    values = list(filter(None, ast.literal_eval(
                        str(item["cpe23Uri"].split(":")).replace("-", "").replace("*", ""))))
                    try:
                        affected_systems = {values[3]: [values[4], values[5]]}
                    except:
                        affected_systems = {values[3]: [values[4]]}
                    total_systems.append(values[4])
                    systems.append(affected_systems)
        affected_systems = self.combine_lists_of_dict(systems)
        cve_affected_systems = ""
        suppliers = []
        for key, value in affected_systems.items():
            if any(isinstance(el, list) for el in value):
                value = [item for sublist in value for item in sublist]
            values = ", ".join(str(v) for v in value)
            cve_affected_systems += "<b>{}:</b> {} ".format(key.capitalize(), values)
            suppliers.append(key.capitalize())
        return cve_affected_systems, suppliers, self.clear_duplicates(total_systems)

    def fetch_cve_changes(self, url):
        """
        This function checks if there are any changes made to the CVE.
        Some CVEs are listed as changed, even though no changes have been made.
        """
        print("[!] Checking changes...".format(url), end="\r")
        response = requests.get("https://nvd.nist.gov/vuln/detail/{}#VulnChangeHistorySection".format(url))
        html = response.content
        soup = bs(html, "lxml")
        time.sleep(0.5)
        data = []
        base_class = soup.find('div', attrs={'class': 'vuln-change-history-container'})
        try:
            table = base_class.find('table',
                                    attrs={'class': 'table table-striped table-condensed table-bordered detail-table'})
            table_body = table.find('tbody')
            rows = table_body.find_all('tr')
            for row in rows:
                data.append([ele for ele in [ele.text.strip() for ele in row.find_all('td')] if ele])
            return self.filter_cve_changes_data(data)
        except:
            return "No changes found."

    def filter_cve_changes_data(self, data):
        """
        This function is responsible for sorting the changes made to CVE.
        The function is not optimized, and should probably be re-written.
        """
        filtered_data = []
        accepted_types = ['Added', 'Changed']
        accepted_configurations = ['CVSS V3.1', 'CVSS V2', 'CPE Configuration']
        for changes in data:
            if changes[0] in accepted_types and changes[1] in accepted_configurations:
                for entry in changes:
                    working_list = []
                    if "*cpe" in entry:
                        if self.user_input["mod_data"]:
                            sections = entry.replace("*", "").replace("-", "").split("\n")
                            for section in sections:
                                section = section.split(":")
                                if len(section) > 1:
                                    section = [i for i in section[3:] if i]
                                    working_list.append(section)
                        else:
                            working_list.append("Affected systems")
                    if "NIST" in entry:
                        cvss_score = entry.split()[1].replace("(", "").replace(")", "")
                        working_list.append(self.calculate_cvss_score(cvss_score))
                    else:
                        if "*" not in entry:
                            working_list.append(entry)
                    filtered_data.append(working_list)
        new_list = []
        for entry in filtered_data:
            for x in entry:
                if isinstance(x, list):
                    for y in x:
                        if y not in new_list:
                            new_list.append(y)
                else:
                    if x not in new_list:
                        new_list.append(x)
        for entry in new_list:
            if entry in accepted_types:
                if entry == accepted_types[0]:
                    new_list[new_list.index(entry)] = '<b style="color: Green"> {} </b><br>'.format(entry)
                else:
                    new_list[new_list.index(entry)] = '<b style="color: Orange"> {} </b><br>'.format(entry)
            if entry in accepted_configurations:
                new_list[new_list.index(entry)] = '<b>{}: </b>'.format(entry)
        final_str = ' '.join([str(elem) for elem in new_list])
        return final_str

    def clear_duplicates(self, input_list):
        """
        The function is used to remove duplicates from a list.
        """
        seen = set()
        unique = []
        for x in input_list:
            if x not in seen:
                unique.append(x)
                seen.add(x)
        return unique

if __name__ == '__main__':
    CVEScanner()
