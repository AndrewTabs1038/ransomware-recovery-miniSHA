transcript off
onbreak {quit -force}
onerror {quit -force}
transcript on

vlib work
vlib riviera/xilinx_vip
vlib riviera/axi_infrastructure_v1_1_0
vlib riviera/axi_vip_v1_1_17
vlib riviera/zynq_ultra_ps_e_vip_v1_0_17
vlib riviera/xil_defaultlib

vmap xilinx_vip riviera/xilinx_vip
vmap axi_infrastructure_v1_1_0 riviera/axi_infrastructure_v1_1_0
vmap axi_vip_v1_1_17 riviera/axi_vip_v1_1_17
vmap zynq_ultra_ps_e_vip_v1_0_17 riviera/zynq_ultra_ps_e_vip_v1_0_17
vmap xil_defaultlib riviera/xil_defaultlib

vlog -work xilinx_vip  -incr "+incdir+C:/Xilinx/Vivado/2024.1/data/xilinx_vip/include" -l xilinx_vip -l axi_infrastructure_v1_1_0 -l axi_vip_v1_1_17 -l zynq_ultra_ps_e_vip_v1_0_17 -l xil_defaultlib \
"C:/Xilinx/Vivado/2024.1/data/xilinx_vip/hdl/axi4stream_vip_axi4streampc.sv" \
"C:/Xilinx/Vivado/2024.1/data/xilinx_vip/hdl/axi_vip_axi4pc.sv" \
"C:/Xilinx/Vivado/2024.1/data/xilinx_vip/hdl/xil_common_vip_pkg.sv" \
"C:/Xilinx/Vivado/2024.1/data/xilinx_vip/hdl/axi4stream_vip_pkg.sv" \
"C:/Xilinx/Vivado/2024.1/data/xilinx_vip/hdl/axi_vip_pkg.sv" \
"C:/Xilinx/Vivado/2024.1/data/xilinx_vip/hdl/axi4stream_vip_if.sv" \
"C:/Xilinx/Vivado/2024.1/data/xilinx_vip/hdl/axi_vip_if.sv" \
"C:/Xilinx/Vivado/2024.1/data/xilinx_vip/hdl/clk_vip_if.sv" \
"C:/Xilinx/Vivado/2024.1/data/xilinx_vip/hdl/rst_vip_if.sv" \

vlog -work axi_infrastructure_v1_1_0  -incr -v2k5 "+incdir+../../../../project_1.gen/sources_1/bd/design_1/ipshared/ec67/hdl" "+incdir+../../../../project_1.gen/sources_1/bd/design_1/ipshared/a317/hdl" "+incdir+C:/Xilinx/Vivado/2024.1/data/xilinx_vip/include" -l xilinx_vip -l axi_infrastructure_v1_1_0 -l axi_vip_v1_1_17 -l zynq_ultra_ps_e_vip_v1_0_17 -l xil_defaultlib \
"../../../../project_1.gen/sources_1/bd/design_1/ipshared/ec67/hdl/axi_infrastructure_v1_1_vl_rfs.v" \

vlog -work axi_vip_v1_1_17  -incr "+incdir+../../../../project_1.gen/sources_1/bd/design_1/ipshared/ec67/hdl" "+incdir+../../../../project_1.gen/sources_1/bd/design_1/ipshared/a317/hdl" "+incdir+C:/Xilinx/Vivado/2024.1/data/xilinx_vip/include" -l xilinx_vip -l axi_infrastructure_v1_1_0 -l axi_vip_v1_1_17 -l zynq_ultra_ps_e_vip_v1_0_17 -l xil_defaultlib \
"../../../../project_1.gen/sources_1/bd/design_1/ipshared/4d04/hdl/axi_vip_v1_1_vl_rfs.sv" \

vlog -work zynq_ultra_ps_e_vip_v1_0_17  -incr "+incdir+../../../../project_1.gen/sources_1/bd/design_1/ipshared/ec67/hdl" "+incdir+../../../../project_1.gen/sources_1/bd/design_1/ipshared/a317/hdl" "+incdir+C:/Xilinx/Vivado/2024.1/data/xilinx_vip/include" -l xilinx_vip -l axi_infrastructure_v1_1_0 -l axi_vip_v1_1_17 -l zynq_ultra_ps_e_vip_v1_0_17 -l xil_defaultlib \
"../../../../project_1.gen/sources_1/bd/design_1/ipshared/a317/hdl/zynq_ultra_ps_e_vip_v1_0_vl_rfs.sv" \

vlog -work xil_defaultlib  -incr -v2k5 "+incdir+../../../../project_1.gen/sources_1/bd/design_1/ipshared/ec67/hdl" "+incdir+../../../../project_1.gen/sources_1/bd/design_1/ipshared/a317/hdl" "+incdir+C:/Xilinx/Vivado/2024.1/data/xilinx_vip/include" -l xilinx_vip -l axi_infrastructure_v1_1_0 -l axi_vip_v1_1_17 -l zynq_ultra_ps_e_vip_v1_0_17 -l xil_defaultlib \
"../../../bd/design_1/ip/design_1_zynq_ultra_ps_e_0_1/sim/design_1_zynq_ultra_ps_e_0_1_vip_wrapper.v" \
"../../../bd/design_1/sim/design_1.v" \

vlog -work xil_defaultlib \
"glbl.v"

