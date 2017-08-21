from hashlib import sha1
from os import stat
import click

class CheckPW:

    def __init__(self, pwdfile):
        self.pwdfile = pwdfile
        self.pwfile = open(self.pwdfile, 'r')
        self._entries = stat(self.pwdfile).st_size // 41

    @property
    def entries(self):
        return self._entries

    def pwdhash(self, pwdclear):
        return sha1(pwdclear.encode()).hexdigest().upper()

    def findpw(self, pwdclear, start=0, end=None):

        pwd = self.pwdhash(pwdclear)

        if end is None:
            end = stat(self.pwdfile).st_size
        current = ( start + end ) // 2

        self.pwfile.seek(current)
        if current != 0:
            baddata = self.pwfile.readline()
        discard = self.pwfile.tell()
        filehash = self.pwfile.readline().strip().upper()

        if not filehash:
            return("Not found")

        if pwd == filehash:
            return("Found")

        if 2 > (end - start):
            return("Not found")

        if filehash > pwd:
            return self.findpw(pwdclear,start,current)
        else:
            return self.findpw(pwdclear,current,end)


@click.command()
@click.option('-p', '--password', default='password')
@click.option('-f', '--pwdfile', default='./data/pwned-pws-combined.txt')
# @click.option('--pwdfile', default='./data/pwdtest.txt')
# @click.option('--pwdfile', default='./data/pwned-passwords-1.0.txt')
# @click.option('--pwdfile', default='./data/pwned-passwords-update-1.txt')
# @click.option('--pwdfile', default='./data/pwned-passwords-update-2.txt')

def run(password, pwdfile):

    check = CheckPW(pwdfile)
    result = check.findpw(password)
    print(f'{check.entries} entries')
    print(f"{result} - Password: {password} Hash: {check.pwdhash(password)}")

if __name__ == '__main__':
    run()
