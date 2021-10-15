# Librecast Modular Multicast Daemon

<a href="https://opensource.org"><img height="150" align="right" src="https://opensource.org/files/OSIApprovedCropped.png" alt="Open Source Initiative Approved License logo"></a>

<a href="https://scan.coverity.com/projects/librestack-lsd-multicast">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/21679/badge.svg"/>
</a>

Modular Multicast Daemon.

## Status

In development.  Pre-alpha.

## Build & Install

Dependencies:
- librecast
- libcurl
- lsdb

`make`
`make install`

## Testing

`sudo make net-setup` (`sudo make net-teardown` when finished)

```sudo ip netns exec vnet0 sudo -u `id -un` /bin/bash```

Now we can run `make test` and `sudo make cap` in our test namespace.


## License

This work is dual-licensed under GPL 2.0 and GPL 3.0.

SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

Copyright © 2020 Brett Sheffield <bacs@librecast.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program (see the file COPYING in the distribution).
If not, see <http://www.gnu.org/licenses/>.

<hr />

# Funding

<p class="bigbreak">
This project was funded through the <a href="https://nlnet.nl/discovery"> NGI0 Discovery </a> Fund, a fund established by NLnet with financial support from the European
Commission's <a href="https://ngi.eu">Next Generation Internet</a> programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 825322. *Applications are still open, you can <a href="https://nlnet.nl/propose">apply today</a>*
</p>


  <a href="https://nlnet.nl/project/LibrecastLive/">
      <img width="250" src="https://nlnet.nl/logo/banner.png" alt="Logo NLnet: abstract logo of four people seen from above" class="logocenter" />
  </a>
  <a href="https://ngi.eu/">
      <img width="250" align="right" src="https://nlnet.nl/image/logos/NGI0_tag.png" alt="Logo NGI Zero: letterlogo shaped like a tag" class="logocenter" />
  </a>
</p>
