%AI_INPUT_PIPELINE  Profiling an Octave training loop's input pipeline with eBPF.
%
%   Run with:  pkg load octave_libbpf;  ai_input_pipeline
%
%   Machine-learning workloads in Octave are frequently bound by the data
%   loader rather than by the arithmetic.  The eBPF program below is a kprobe
%   on vfs_read() that records a histogram of the *requested read size* for
%   every read issued by the process.  Small reads mean the loader is paging
%   through the dataset in tiny pieces; large reads mean it streams.
%
%   The example trains nothing - it runs the same "minibatch loop" twice,
%   once with 4 KiB batches and once with 1 MiB batches, and shows what the
%   kernel sees.  The histogram and the wall clock are produced by the real
%   kernel and by Octave, not by the example.

pkg load octave_libbpf

if (~ bpf.have_bpf ())
  printf ('skipped: this process may not load eBPF programs\n');
  return;
end

R = bpf.regs ();

%% ---- the observation program: histogram of vfs_read() sizes (in KiB) ----
b = bpf.Builder ('GPL');
reads = b.map ('read_sizes', 'array', 'u32', 'u64', 8);

p = b.program ('kprobe/vfs_read', 'read_hist');
p.ldx_dw (R.R2, R.R1, 96);                            % arg3 = size_t count
p.rsh64_imm (R.R2, 10);                               % -> KiB
p.jle_imm (R.R2, 7, 'clamped');
p.mov64_imm (R.R2, 7);                                % clamp to the last bucket
p.label ('clamped');
p.stx_w (R.R10, R.R2, -4);                            % u32 key = bucket
p.ld_map_fd (R.R1, 'read_sizes');
p.mov64_reg (R.R2, R.R10);
p.add64_imm (R.R2, -4);
p.call (bpf.helper ('map_lookup_elem'));
p.jeq_imm (R.R0, 0, 'done');
p.mov64_imm (R.R1, 1);
p.atomic_dw (R.R0, R.R1, 0, bpf.atomic_op ('add'));
p.label ('done');
p.mov64_imm (R.R0, 0);
p.exit ();

obj = b.build ();
obj.load ();
links = obj.attach_all ();          %#ok<NASGU>
hist = obj.find_map ('read_sizes');

%% ---- a dataset and the two minibatch loops --------------------------------
dataset = tempname ();
fid = fopen (dataset, 'wb');
fwrite (fid, uint8 (mod (0:4*1024*1024-1, 251)), 'uint8');
fclose (fid);

function [secs, checksum] = minibatch_loop (path, batch)
  fid = fopen (path, 'r');
  unwind_protect
    checksum = 0;
    t = tic ();
    while (true)
      blk = fread (fid, batch, 'uint8');
      if (isempty (blk))
        break;
      end
      checksum = checksum + double (blk(1)) + numel (blk);   % stand-in for the step
    end
    secs = toc (t);
  unwind_protect_cleanup
    fclose (fid);
  end_unwind_protect
end

labels = {'<1 KiB', '1-2 KiB', '2-3 KiB', '3-4 KiB', ...
          '4-5 KiB', '5-6 KiB', '6-7 KiB', '>=7 KiB'};

function show_hist (hist, labels, title)
  v = zeros (1, 8);
  for k = 0:7
    v(k+1) = hist.lookup (k);
  end
  printf ('%s: ', title);
  printf ('%s ', labels{find (v > 0)});
  printf ('\n');
  printf ('   总请求数 %d, 分布 %s\n', sum (v), mat2str (v));
end

printf ('--- 4 KiB minibatches (poor input pipeline) ---\n');
[a_secs, a_sum] = minibatch_loop (dataset, 4096);
show_hist (hist, labels, 'read() 大小直方图');

for k = 0:7
  hist.update (k, 0);
end

printf ('\n--- 1 MiB minibatches (streaming input pipeline) ---\n');
[b_secs, b_sum] = minibatch_loop (dataset, 1024*1024);
show_hist (hist, labels, 'read() 大小直方图');

printf ('\n4 KiB 批次耗时 %.3f s，1 MiB 批次耗时 %.3f s（校验和相同：%d）\n', ...
        a_secs, b_secs, a_sum == b_sum);

unlink (dataset);
clear obj
