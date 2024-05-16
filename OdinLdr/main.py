import sys
import pefile

def printAscciart(): 
    print(r"""
       .__           .__  .__                   .___                                                  __             .___
  _____|  |__   ____ |  | |  |   ____  ____   __| _/____      ____   ____   ____   ________________ _/  |_  ____   __| _/
 /  ___/  |  \_/ __ \|  | |  | _/ ___\/  _ \ / __ |/ __ \    / ___\_/ __ \ /    \_/ __ \_  __ \__  \\   __\/ __ \ / __ | 
 \___ \|   Y  \  ___/|  |_|  |_\  \__(  <_> ) /_/ \  ___/   / /_/  >  ___/|   |  \  ___/|  | \// __ \|  | \  ___// /_/ | 
/____  >___|  /\___  >____/____/\___  >____/\____ |\___  >  \___  / \___  >___|  /\___  >__|  (____  /__|  \___  >____ | 
     \/     \/     \/               \/           \/    \/  /_____/      \/     \/     \/           \/          \/     \/ 
    """)

def extract_text_section(file_path, output_file_path):
    try:
        pe = pefile.PE(file_path)

        for section in pe.sections:
            if ".text" in section.Name.decode('utf-8'):
                text_section_data = section.get_data()

                with open(output_file_path, "wb") as output_file:
                    output_file.write(text_section_data)

                printAscciart()
                return

        

    except Exception as e:
        print(f"ERROR : {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(1)

    fichier_exe = sys.argv[1]
    output_file = sys.argv[2]

    extract_text_section(fichier_exe, output_file)
