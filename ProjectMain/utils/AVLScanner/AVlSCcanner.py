import os
import subprocess

def Scanner(filepath,file=1):
    filepath=os.path.abspath(filepath)
    if file==1:
        cmd = 'cd ProjectMain/utils/AVLScanner && ./AVLScanner -c Config/top.ct -f ' + filepath
    # cmd = 'cd '+os.getcwd()+'/ProjectMain/utils/AVLScanner \n AVLScanner.exe -c Config/top.ct -p '+filepath
    else:
        cmd ='cd ProjectMain/utils/AVLScanner && ./AVLScanner -c Config/top.ct -p '+filepath
    if os.path.exists(filepath):
        rc,out=None,None
        try:
            rc,out=subprocess.getstatusoutput(cmd)
        except(Exception):
            pass
        return out.strip('\t').split('\n')
    return None