classdef BTF < handle
%BPF.BTF  BPF Type Format information.
%
%   B = bpf.BTF.from_file (PATH)     parse the .BTF section of an ELF file
%   B = bpf.BTF.from_raw (BYTES)     parse a raw BTF blob
%   B = bpf.BTF.vmlinux ()           the running kernel's BTF
%   B = bpf.BTF.kernel (BTF_ID)
%   B = bpf.BTF.new_empty ()         an empty BTF, ready for bpf.Btf
%   B = bpf.BTF (PTR, OWNED)         wrap an existing 'struct btf *'
%
%   Introspection
%   -------------
%     n = B.type_cnt ()
%     i = B.type_info (ID)           struct: id, name, kind, vlen, size, type
%     i = B.find_by_name (NAME)      type id, 0 when not found
%     i = B.find_by_name_kind (NAME, KIND)
%     s = B.name_by_offset (OFF)
%     r = B.raw_data ()              the BTF blob
%     s = B.dump ([ID])              C like declaration(s)
%     m = B.members (ID)             members of a struct/union (name, type,
%                                    bit offset, bitfield width, byte offset)
%
%   Using it
%   --------
%     f = B.load_into_kernel ()      load and return a BTF file descriptor
%     f = B.fd ()
%
%   Constants for the type kinds are properties of this class, for example
%   bpf.BTF.KIND_STRUCT.
%
%   See also bpf.Btf, bpf.Object.

  properties
    ptr = uint64 (0);
    owned = true;
  end

  properties (Constant)
    KIND_UNKN = 0;
    KIND_INT = 1;
    KIND_PTR = 2;
    KIND_ARRAY = 3;
    KIND_STRUCT = 4;
    KIND_UNION = 5;
    KIND_ENUM = 6;
    KIND_FWD = 7;
    KIND_TYPEDEF = 8;
    KIND_VOLATILE = 9;
    KIND_CONST = 10;
    KIND_RESTRICT = 11;
    KIND_FUNC = 12;
    KIND_FUNC_PROTO = 13;
    KIND_VAR = 14;
    KIND_DATASEC = 15;
    KIND_FLOAT = 16;
    KIND_DECL_TAG = 17;
    KIND_TYPE_TAG = 18;
    KIND_ENUM64 = 19;
  end

  methods

    function b = BTF (ptr, owned)
      if (nargin < 1 || isempty (ptr))
        return;
      end
      b.ptr = uint64 (ptr);
      if (nargin > 1)
        b.owned = logical (owned);
      end
    end

    function delete (obj)
      if (obj.owned && obj.ptr ~= 0)
        try
          libbpf_wrap ('btf_free', obj.ptr);
        catch
        end
      end
      obj.ptr = uint64 (0);
    end

    function n = type_cnt (obj)
      n = libbpf_wrap ('btf_type_cnt', obj.ptr);
    end

    function i = type_info (obj, id)
      i = libbpf_wrap ('btf_type_info', obj.ptr, id);
    end

    function id = find_by_name (obj, name)
      id = libbpf_wrap ('btf_find_by_name', obj.ptr, name);
    end

    function id = find_by_name_kind (obj, name, kind)
      id = libbpf_wrap ('btf_find_by_name_kind', obj.ptr, name, kind);
    end

    function s = name_by_offset (obj, off)
      s = libbpf_wrap ('btf_name_by_offset', obj.ptr, off);
    end

    function m = members (obj, id)
      %M  结构体或联合体的成员列表
      %   M = B.members (TYPE_ID) 返回一个结构体数组，字段为
      %   name、type、offset（比特）、bitfield（位域宽度，0 表示普通成员）
      %   和 bytes（offset/8，便于直接作为 ldx/stx 指令的偏移使用）。
      %   对于非结构体/联合体类型返回 []。
      %
      %   这是在没有 CO-RE 重定位的情况下，用内核 BTF 动态解析结构体成员
      %   偏移的方式：在 Octave 里查一次偏移，再把它作为立即数写进 eBPF
      %   指令，程序本身不必包含任何版本相关的常量。
      m = libbpf_wrap ('btf_members', obj.ptr, id);
    end

    function r = raw_data (obj)
      r = libbpf_wrap ('btf_raw_data', obj.ptr);
    end

    function s = dump (obj, id)
      if (nargin < 2 || isempty (id))
        s = libbpf_wrap ('btf_dump', obj.ptr);
      else
        s = libbpf_wrap ('btf_dump', obj.ptr, id);
      end
    end

    function f = fd (obj)
      f = libbpf_wrap ('btf_fd', obj.ptr);
    end

    function f = load_into_kernel (obj)
      f = libbpf_wrap ('btf_load_into_kernel', obj.ptr);
    end

    function disp (obj)
      fprintf ('  bpf.BTF types=%d fd=%d\n', obj.type_cnt (), obj.fd ());
    end
  end

  methods (Static)

    function b = from_file (path)
      p = libbpf_wrap ('btf_parse_elf', path);
      b = bpf.BTF (p, true);
    end

    function b = from_raw (data)
      b = bpf.BTF (libbpf_wrap ('btf_parse_raw', data), true);
    end

    function b = new_empty ()
      b = bpf.BTF (libbpf_wrap ('btf_new_empty'), true);
    end

    function b = vmlinux ()
      b = bpf.BTF (libbpf_wrap ('btf_load_vmlinux'), true);
    end

    function b = kernel (id)
      b = bpf.BTF (libbpf_wrap ('btf_load_from_kernel_by_id', id), true);
    end
  end
end
