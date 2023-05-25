################################################################################
# Configure a box for the custom ssh example challenge.
################################################################################


import sys
import os
import subprocess
import re
import zlib
import json


def main():
    try:
        # Generate password from seed =========================================
        seed = os.environ.get("SEED")

        if seed == "":
            print("Seed was not read from filesystem. Aborting.")
            sys.exit(1)

        password = hex(zlib.crc32(seed.encode()))
        password = password[2:]

        # =====================================================================

        # Make new dirs =======================================================
        subprocess.run(["/bin/sh", "-c", "mkdir /home/ctf-player"], check=True)

        subprocess.run(["/bin/sh", "-c", "mkdir /home/ctf-player/blargh"], check=True)

        # =====================================================================

        # Create ctf-player user
        subprocess.run(
            [
                "/usr/sbin/useradd",
                "-U",
                "ctf-player",
                "-d",
                "/home/ctf-player",
                "-s",
                "/usr/local/Special.py",
            ],
            check=True,
        )

        # Pipe the output of echo into chpasswd to change password of
        # ctf-user
        pEcho = subprocess.Popen(
            ("echo", f"ctf-player:{password}"), stdout=subprocess.PIPE
        )

        output = subprocess.check_output(("chpasswd"), stdin=pEcho.stdout)

        pEcho.wait()

        # Make sure ownership is changed to ctf-player
        subprocess.run(
            [
                "/usr/bin/chown",
                "-R",
                "ctf-player:ctf-player",
                "/home/ctf-player/",
            ],
            check=True,
        )

        # Copy profile to ctf-player
        # subprocess.run(
        #    [
        #        "/usr/bin/cp",
        #        "/challenge/profile",
        #        "/home/ctf-player/.profile",
        #    ],
        #    check=True,
        # )

        # =====================================================================

        # Split flag into 3 parts  ============================================
        flag = os.environ.get("FLAG")

        if flag == "":
            print("Flag was not read from environment. Aborting.")
            sys.exit(-1)
        else:
            # Get hash part
            flag_rand = re.search("{.*}$", flag)
            if flag_rand == None:
                print("Flag isn't wrapped by curly braces. Aborting.")
                sys.exit(-2)
            else:
                flag_rand = flag_rand.group()
                flag_rand = flag_rand[1:-1]

        flag = "picoCTF{5p311ch3ck_15_7h3_w0r57_" + flag_rand + "}"

        with open("/home/ctf-player/blargh/flag.txt", "w") as f:
            f.write(flag)

        # =====================================================================

        # Create and update metadata.json =====================================

        metadata = {}
        metadata["flag"] = str(flag)
        metadata["password"] = str(password)
        json_metadata = json.dumps(metadata)

        with open("/challenge/metadata.json", "w") as f:
            f.write(json_metadata)

        # =====================================================================

    except subprocess.CalledProcessError:
        print("A subprocess has returned an error code")
        sys.exit(1)


# =============================================================================


if __name__ == "__main__":
    main()
