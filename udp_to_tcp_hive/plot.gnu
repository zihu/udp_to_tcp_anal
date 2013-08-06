#gnuplot script
set xlabel 'top N clients'
set ylabel '# of tcp connections'

set xr [0:1000]

set term postscript eps color enh

plot "tcpconn_cdf.dat" using 2:3 with lines title "RTT=50ms"

#del_tld_data(tld)=sprintf("<awk '$2==\"%s\"  {print $0}' %s | head -1", tld, datafile)
#plot del_tld_data("xxx") using 3:(funcs($3)):3:(funce($3)) with vectors nohead lc 1 notitle,\
#del_tld_data("asia") using 3:(funcs($3)):3:(funce($3)) with vectors nohead lc 2 notitle,\
#del_tld_data("cw") using 3:(funcs($3)):3:(funce($3)) with vectors nohead lc 3 notitle,\
#del_tld_data("tel") using 3:(funcs($3)):3:(funce($3)) with vectors nohead lc 4 notitle,\
#del_tld_data("xn--fiqs8s") using 3:(funcs($3)):3:(funce($3)) with vectors lc 5 nohead notitle,\
#del_tld_data("kp") using 3:(funcs($3)):3:(funce($3)) with vectors nohead lc 6 notitle,\
#del_tld_data("sx") using 3:(funcs($3)):3:(funce($3)) with vectors nohead lc 7 notitle

