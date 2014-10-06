#!/system/bin/sh
DPATH="/sys/kernel/debug/tracing"
LPATH="/sys/kernel/debug/binder"
DATE=$(date +%Y%m%d%H%M%S)
echo nop > $DPATH/current_tracer
echo > $DPATH/trace
echo > $DPATH/trace_pipe

# set function tracer
echo '*binder*' '*bcmd*'> $DPATH/set_ftrace_filter
echo 'counter_get_cntvct_cp15' > $DPATH/set_ftrace_notrace
echo function_graph > $DPATH/current_tracer
echo funcgraph-abstime > $DPATH/trace_options
#ps -t > /sdcard/binder_ftrace_ref_$DATE.txt
# start the tracing
echo 1 > $DPATH/tracing_on
cat $DPATH/trace_pipe > /sdcard/binder_ftrace_$DATE.txt &




