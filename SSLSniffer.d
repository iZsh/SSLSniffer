#!/usr/sbin/dtrace -Cws
# socket communication dumper with SSL support
# copyright 2009 by iZsh (izsh at iphone-dev.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# ==================
#  General Comments
# ==================
#
# Initially based on a script from pumpkin, but completely rewritten
# to intercept messages at the SSL command level instead of the CoreFoundation
# level (which therefore only dumped plist-based messages using the standard
# CF API functions). 
#
# Intercepting at the SSL level directly is a little bit bitchy because of
# many tail-calls.
#
# Also this version doesn't dump hex yet, only asciis. Dumping hexdump
# without extra large output might be a little bit tricky (I'm not a dtrace
# wizard) because dtrace's output print size is fixed, so you would always
# have to print out the same amout of byte, even when there are less bytes in
# the packet.
#
# There are probably bugs or possible improvements to be made, feel free
# to mail me patches.
#
# =======
#  Usage
# =======
#
# Usage example: sudo SSLSniffer.d -p <pid> or sudo SSLSniffer.d -c /path-to
# By the way, if you want to attach to iTunes, you will need the
# pt_deny_attach kext available at http://landonf.bikemonkey.org/code/macosx

#pragma D option quiet
#pragma D option switchrate=10
#pragma D option bufsize=32M 
#pragma D option dynvarsize=1M 

/* 128K appears to be the limit in MobileDevice, so let's be twice as large just to be safe ;) */
#pragma D option strsize=256K

BEGIN 
{ 
  freopen("sslsniff.txt");
}

/****************************************************************************/

pid$target::SSL_write:entry
{
  self->send_message = (char *)copyin(arg1, arg2);
  self->send_message[arg2] = 0;

  printf("\n\n\n============ SSL_write(0x%p, 0x%p, %.8d) ============\n",
		arg0, arg1, arg2);
//	tracemem(self->send_message, 16384);
  printf("%s\n", stringof(self->send_message));
  printf("=====================================================================\n");
  
  self->send_message = 0;
  self->dump_send = 0;
}

pid$target::SSL_write:return
{
  self->dump_send = 1;
}


pid$target::send:entry
/self->dump_send == 1/
{
  self->send_message = (char *)copyin(arg1, arg2);
  self->send_message[arg2] = 0;

  printf("\n\n\n============== send(0x%p, 0x%p, %.8d) ==============\n",
		arg0, arg1, arg2);
//	tracemem(self->send_message, 16384);
  printf("%s\n", stringof(self->send_message));
  printf("=====================================================================\n");
  
  self->send_message = 0;
}

/****************************************************************************/
//pid$target::ssl[0-9]*_read_internal:entry, pid$target::ssl_read:entry
pid$target::ssl[0-9]*_read:entry
{
  self->read_arg0 = arg0;
  self->read_arg1 = arg1;
  self->dump_read = 0;
}

pid$target::ssl[0-9]*_read_internal:return, pid$target::ssl_read:return
{
    self->read_message = (char *)copyin(self->read_arg1, arg1);
    self->read_message[arg1] = 0;

	  printf("\n\n\n============ SSL_read(0x%p, 0x%p, %.8d) ============\n",
			self->read_arg0, self->read_arg1, arg1);
//		tracemem(self->read_message, 16384);
	  printf("%s\n", stringof(self->read_message));
	  printf("====================================================================\n");

	  self->read_message = 0;
	  self->read_arg0 = 0;
	  self->read_arg1 = 0;
	  self->dump_read = 1;
}

pid$target::recv:entry
/self->dump_read == 1/
{
	self->read_arg0 = arg0;
	self->read_arg1 = arg1;
}

pid$target::recv:return
/self->dump_read == 1/
{
  self->read_message = (char *)copyin(self->read_arg1, arg1);
  self->read_message[arg1] = 0;

  printf("\n\n\n============== recv(0x%p, 0x%p, %.8d) ==============\n",
		self->read_arg0, self->read_arg1, arg1);
//	tracemem(self->read_message, 16384);
  printf("%s\n", stringof(self->read_message));
  printf("==============================================================\n");

  self->read_message = 0;
  self->read_arg0 = 0;
  self->read_arg1 = 0;
}
