# for 1 PNG output
#set term png size 1700, 570
# Origin
#set term png size 1750, 570
#set term png size 2100, 600
#set term pngcairo size 1750, 570
set term png size 1800, 570
#set term png size 1200, 1200
#set term pngcairo size 1750, 570
#set term pdfcairo size 2100, 600
set output "fig_pop_heatmap.png"
# for view
#set term qt size 1800, 550
set size square 1, 1
#set size ratio 1.5

unset key
# traditional color
#set palette rgb 7,5,15
# hot
#set palette rgb 21,22,23
# AFM hot
#set palette rgb 34,35,36
# Gray
#set palette gray
# Custom
#set palette model XYZ functions gray**0.15, gray**0.5, gray**1.0
# Custom 1
#set palette define (\
#	0 '#101010', \
#	1 '#ee0000', \
#	2 '#ffa000', \
#	3 '#ffee33')
# Custom 2
#set palette define (\
#	0 '#000000', \
#	1 '#ee0000', \
#	2 '#ffb080', \
#	3 '#ffee80', \
#	4 '#ffffff')
set palette define (\
	0 '#ffffff`', \
	1 '#000000')

#set cbrange [0:6]
#set xrange [0: 128]
#set yrange [0: 128]
set cbrange [0:1]
set xrange [0: 256]
#set yrange [0: 4096]
set yrange [0: 256]
set xlabel "Offset of Gadget" offset 0, -1.8
set ylabel "Offset of Branch Target" offset -1.2
#set cblabel "Prevalence" offset 2.2
#unset cblabel
unset colorbox

set xlabel font "Times-New-Roman, 20"
set ylabel font "Times-New-Roman, 20"
set cblabel font "Times-New-Roman, 20"
set ytics font "Times-New-Roman, 19" out
set xtics font "Times-New-Roman, 19" out
set cbtics font "Times-New-Roman, 19"
set title font "Times-New-Roman, 22" offset 0,0.5

#set xtics 0,64,256
#set xtics 0,16,128
#set xtics 0,1024,4096
set xtics 0,32,256
#set xtics ("" 0, "0x200" 16, "0x400" 32, "0x600" 48, "0x800" 64, "0xa00" 80, "0xc00" 96, "0xe00" 112, "0x1000" 128)
set xtics ("" 0, "0x400" 64, "0x800" 128, "0xc00" 192, "0x1000" 256)
#set xtics rotate by 60 offset 0.3,0.6 right
set xtics rotate by 60 offset 0.7,-0.1 right

set ytics 0,32,256
#set ytics 0,512,4096
#set ytics 0,16,4096
#set ytics ("0" 0, "0x200" 16, "0x400" 32, "0x600" 48, "0x800" 64, "0xa00" 80, "0xc00" 96, "0xe00" 112, "0x1000" 128) offset 0.8, -0.5
#set ytics ("0" 0, "0x400" 1024, "0x800" 2048, "0xc00" 3072, "0x1000" 4096) offset 0.8, -0.5
#set ytics ("0" 0, "0x40" 64, "0x80" 128, "0xc0" 192, "0x100" 256)
set ytics ("0" 0, "0x400" 64, "0x800" 128, "0xc00" 192, "0x1000" 256)
set ytics rotate by 60 offset 0.8,-0.0 right

set cbtics 0,1,6 offset -0.9, -0.5
#unset cbtics

# assist line
#set arrow 10 from 0, 64 to 256, 64 nohead lt rgb "red"

set multiplot layout 1,4 columns #scale 0.95,0.95
# Origin
#set lmargin 7.5
set lmargin 11
# Origin
set rmargin 3 
#set rmargin 1 
set bmargin 0
set tmargin 0
set view map
#set pm3d map

# Emphasize spot
#set pm3d corners2color max
#set pm3d corners2color c4
#set pm3d interpolate 0,0
#set pm3d nolighting
set title "(a) Clang/LLVM CFI with CET \n and commodity configuration"
#splot 'KCFI_CET/kernel_disasm/ubuntu/00.results/06.aligned_branch_position.txt' matrix with pm3d
plot 'KCFI_CET/kernel_disasm/ubuntu/00.results/06.aligned_branch_position.txt' matrix with image pixels

set title "(b) Clang/LLVM CFI with CET \n and kernel default configuration"
#splot 'KCFI_CET/kernel_disasm/default/00.results/06.aligned_branch_position.txt' matrix with pm3d
plot 'KCFI_CET/kernel_disasm/default/00.results/06.aligned_branch_position.txt' matrix with image pixels

set title "(c) FineIBT and \n commodity configuration"
#splot 'FineIBT/kernel_disasm/ubuntu/00.results/06.aligned_branch_position.txt' matrix with pm3d
plot 'FineIBT/kernel_disasm/ubuntu/00.results/06.aligned_branch_position.txt' matrix with image pixels

set title "(d) FineIBT and \n kernel default configuration"
#splot 'FineIBT/kernel_disasm/default/00.results/06.aligned_branch_position.txt' matrix with pm3d 
plot 'FineIBT/kernel_disasm/default/00.results/06.aligned_branch_position.txt' matrix with image pixels
unset multiplot

