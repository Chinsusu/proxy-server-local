# Security Notes

- Chạy `pgw-agent` với quyền tối thiểu đủ để `nft -f -`.
- Hạn chế bind ra public (chỉ 127.0.0.1) trừ khi có reverse proxy/ngăn chặn thích hợp.
- SNI/domain logging: đã ẩn thông tin nhạy cảm; không lưu headers/body.
- Chặn leak: filter chain block oifname WAN & block UDP từ client.
