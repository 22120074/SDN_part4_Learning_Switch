# README.md - SDN Level 3: Learning Router

## Người làm bài
- Tên: [Đỗ Nhật Duy]

## Giới thiệu
Phần này là phần cuối cùng trong chuỗi bài tập về SDN, giúp sinh viên hiểu cách xây dựng và triển khai một bộ định tuyến động (Learning Router) trên mạng SDN bằng cách sử dụng Mininet và bộ điều khiển POX. Dưới đây là các bước hướng dẫn chi tiết và những gì cần hoàn thành cho bài tập này.

---

## Yêu cầu đề bài
- Learing Objectives (After this section, students will be able to…):

  - Write a program to handle ARP requests and generate valid ARP replies to establish connectivity without static address mappings.
  - Dynamically create match –> action rules that correctly forward L3 traffic across multiple distinct L2 networks with dynamic L2 addresses.
  - Create an SDN controller program capable of holding dynamic state to configure multiple switches in response to traffic observed in the network.
  - Reason about the relationship between L2 addresses within a particular subnet and the L3 addresses used for internetwork routing.
- For part 4, we’ll extend your part 3 code to implement a more realistic level-3 router out of the cores21 switch. The part4controller.py skeleton is very similar to part3, and you may want to begin by copying forward some of your functionality from part3. For the topology, we again provide a file (part4.py). The difference between part3.py and part4.py topologies is that there is no longer a static L3<–>L2 address mapping loaded into each host, and the default route 'h{N}0-eth0' was changed to 'via 10.0.{N}.1' where ‘10.0.{N}.1’ is the IP address of the gateway (i.e. router) for that particular subnet. This effectively changes the network from a switched network (with hosts sending to a MAC address) into a routed network (hosts sending to an IP address which may require a gateway out of the L2 network). A minimal part3controller will not work on this new topology!

- To handle this L2<–>L3 mapping cores21 will need to:

  - Handle ARP traffic in multiple subnets (without forwarding);
  - Generate valid ARP replies when needed; and
  - Forward IP traffic across link domains (which will require updating the L2 header);
- Additionally, this assignment requires that your implementation work dynamically. You may not install static routes on cores21 at startup. Instead, your router must learn which ports and which L2 addresses correspond to particular L3 addresses, and install the appropriate rules into the cores21 switch dynamically. This information can be inferred by processing the content of received ARP messages, or possibly other traffic on the network (although processing ARP is sufficient). You may handle each of the individual ARP packets in the controller (i.e., not with flow rules) for part 4, but most IP traffic should be handled with flow rules for efficiency. The other switches (e.g., s1) do not need to be modified and can continue to flood traffic with static rules.

## Mục tiêu học tập
Sau khi hoàn thành phần này, sinh viên sẽ có khả năng:

1. Xử lý các yêu cầu ARP và tạo phản hồi ARP hợp lệ để thiết lập kết nối mà không cần ánh xạ địa chỉ tĩnh.
2. Tạo các quy tắc **match → action** động để chuyển tiếp lưu lượng lớp 3 (L3) qua nhiều mạng lớp 2 (L2) khác nhau với địa chỉ L2 động.
3. Viết chương trình điều khiển SDN có khả năng lưu trữ trạng thái động để cấu hình nhiều switch theo các gói dữ liệu quan sát được trong mạng.
4. Hiểu mối quan hệ giữa địa chỉ L2 trong một subnet và địa chỉ L3 dùng cho định tuyến giữa các mạng.

---

## Cấu trúc mạng và bài tập
### Topology

```
[h10@10.0.1.10/24]--{s1}--\
[h20@10.0.2.20/24]--{s2}--{cores21}--{dcs31}--[serv1@10.0.4.10/24]
[h30@10.0.3.30/24]--{s3}--/    |
                               |
                    [hnotrust1@172.16.10.100/24]
```

1. **Mô tả**:
   - Cấu trúc mạng có nhiều subnet và switch, với một switch trung tâm ({cores21}) thực hiện vai trò của bộ định tuyến.
   - `hnotrust1` đại diện cho một mạng không đáng tin cậy và cần được hạn chế.

2. **Yêu cầu**:
   - Xử lý lưu lượng ARP để thiết lập ánh xạ địa chỉ động giữa L2 và L3.
   - Chuyển tiếp lưu lượng IP giữa các subnet bằng cách cập nhật tiêu đề L2.
   - Áp dụng chính sách:
     - Chặn mọi lưu lượng IP từ `hnotrust1` tới `serv1`.
     - Chặn lưu lượng ICMP từ `hnotrust1` tới các host trong mạng nội bộ.

---

## Hướng dẫn triển khai

### Xử lý ARP
- Bộ điều khiển phải xử lý gói ARP mà không chuyển tiếp gói này.
- Sinh viên cần tạo các phản hồi ARP hợp lệ khi nhận yêu cầu từ các host.

### Chuyển tiếp lưu lượng IP
- Bộ điều khiển sẽ:
  1. Học địa chỉ L2 của các thiết bị trong mạng bằng cách phân tích các gói ARP nhận được.
  2. Tạo các quy tắc **flow** động trong `cores21` để chuyển tiếp lưu lượng IP dựa trên thông tin đã học.

### Cập nhật chính sách từ Part 3
- Các quy tắc chặn (block rules) và cho phép (allow rules) cần được thực hiện dựa trên:
  - Nguồn (source IP).
  - Đích (destination IP).
  - Loại giao thức (ICMP, IP).

---
