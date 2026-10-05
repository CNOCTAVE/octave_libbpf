%RINGBUF_TRACEPOINT  Stream events to Octave through a BPF ring buffer.
%
%   Run with:  pkg load octave_libbpf;  ringbuf_tracepoint
%
%   A raw tracepoint program runs on every system call entry, fills a small
%   event record with the current pid and submits it to a BPF ring buffer.
%   Octave then polls the ring buffer and prints the samples it receives.

pkg load octave_libbpf

R = bpf.regs ();

b = bpf.Builder ('GPL');
events = b.map ('events', 'ringbuf', [], [], 4096);

p = b.program ('raw_tp/sys_enter', 'on_sys_enter');
p.st_w (R.R10, -8, 0);                          % event = {0, 0}
p.st_w (R.R10, -4, 0);
p.call (bpf.helper ('get_current_pid_tgid'));   % r0 = (tgid << 32) | pid
p.mov64_reg (R.R1, R.R0);
p.rsh64_imm (R.R1, 32);
p.stx_w (R.R10, R.R1, -8);                      % event.pid = tgid
p.ld_map_fd (R.R1, 'events');
p.mov64_reg (R.R2, R.R10);
p.add64_imm (R.R2, -8);
p.mov64_imm (R.R3, 8);                          % sizeof (event)
p.mov64_imm (R.R4, 0);                          % flags
p.call (bpf.helper ('ringbuf_output'));
p.mov64_imm (R.R0, 0);
p.exit ();

obj = b.build ();
obj.load ();
links = obj.attach_all ();       %#ok<NASGU>

rb = bpf.RingBuf (obj.find_map ('events'));

% produce some system calls
for k = 1:20
  fid = fopen ('/etc/hostname', 'r');
  if (fid > 0)
    fclose (fid);
  end
end

[samples, lost] = rb.poll (500, 16);   % wait up to 500 ms, at most 16 samples

printf ('received %d samples (%d lost)\n', numel (samples), lost);
for k = 1:min (numel (samples), 5)
  s = samples{k};
  pid = bpf.bytes2num (s(1:4));
  printf ('  sample %d: pid = %d (%d bytes)\n', k, pid, numel (s));
end

clear obj rb
