#!/bin/sh
wget https://cernvm.cern.ch/releases/image.list --no-check-certificate -O cernvm.list
wget http://mwdev04.is.ed.ac.uk/lists/image_list --no-check-certificate -O eduk.list
wget https://particle.phys.uvic.ca/~igable/hepix/hepix_signed_image_list --no-check-certificate -O ian.list
wget http://www.cnaf.infn.it/~chierici/repo/andrea-list --no-check-certificate -O andrea.list

