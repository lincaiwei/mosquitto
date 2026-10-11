/*
Copyright (c) 2010-2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
   Tatsuzo Osawa - Add epoll.
*/

#ifndef MOSQUITTO_INTERNAL_H
#define MOSQUITTO_INTERNAL_H

#include "config.h"

#ifdef WIN32
#  include <winsock2.h>
#endif

#ifdef WITH_TLS
#  include <openssl/ssl.h>
#else
#  include <time.h>
#endif
#include <stdlib.h>

#if defined(WITH_THREADING) && !defined(WITH_BROKER)
#  include <pthread.h>
#else
#  include <dummypthread.h>
#endif

#ifdef WITH_SRV
#  include <ares.h>
#endif

#ifdef WIN32
#	if _MSC_VER < 1600
		typedef unsigned char uint8_t;
		typedef unsigned short uint16_t;
		typedef unsigned int uint32_t;
		typedef unsigned long long uint64_t;
#	else
#		include <stdint.h>
#	endif
#else
#	include <stdint.h>
#endif

#include "mosquitto.h"
#include "time_mosq.h"
#ifdef WITH_BROKER
#  ifdef __linux__
#    include <netdb.h>
#  endif
#  include "uthash.h"
struct mosquitto_client_msg;
#endif

#ifdef WIN32
typedef SOCKET mosq_sock_t;
#else
typedef int mosq_sock_t;
#endif

#define SAFE_PRINT(A) (A)?(A):"null"

enum mosquitto_msg_direction {
	mosq_md_in = 0,
	mosq_md_out = 1
};

enum mosquitto_msg_state {
	mosq_ms_invalid = 0,
	mosq_ms_publish_qos0 = 1,
	mosq_ms_publish_qos1 = 2,
	mosq_ms_wait_for_puback = 3,
	mosq_ms_publish_qos2 = 4,
	mosq_ms_wait_for_pubrec = 5,
	mosq_ms_resend_pubrel = 6,
	mosq_ms_wait_for_pubrel = 7,
	mosq_ms_resend_pubcomp = 8,
	mosq_ms_wait_for_pubcomp = 9,
	mosq_ms_send_pubrec = 10,
	mosq_ms_queued = 11
};

enum mosquitto_client_state {
	mosq_cs_new = 0,
	mosq_cs_connected = 1,
	mosq_cs_disconnecting = 2,
	mosq_cs_active = 3,
	mosq_cs_connect_pending = 4,
	mosq_cs_connect_srv = 5,
	mosq_cs_disconnect_ws = 6,
	mosq_cs_disconnected = 7,
	mosq_cs_socks5_new = 8,
	mosq_cs_socks5_start = 9,
	mosq_cs_socks5_request = 10,
	mosq_cs_socks5_reply = 11,
	mosq_cs_socks5_auth_ok = 12,
	mosq_cs_socks5_userpass_reply = 13,
	mosq_cs_socks5_send_userpass = 14,
	mosq_cs_expiring = 15,
	mosq_cs_duplicate = 17, /* client that has been taken over by another with the same id */
	mosq_cs_disconnect_with_will = 18,
	mosq_cs_disused = 19, /* client that has been added to the disused list to be freed */
	mosq_cs_authenticating = 20, /* Client has sent CONNECT but is still undergoing extended authentication */
	mosq_cs_reauthenticating = 21, /* Client is undergoing reauthentication and shouldn't do anything else until complete */
};

enum mosquitto__protocol {
	mosq_p_invalid = 0,
	mosq_p_mqtt31 = 1,
	mosq_p_mqtt311 = 2,
	mosq_p_mqtts = 3,
	mosq_p_mqtt5 = 5,
};

enum mosquitto__threaded_state {
	mosq_ts_none,		/* No threads in use */
	mosq_ts_self,		/* Threads started by libmosquitto */
	mosq_ts_external	/* Threads started by external code */
};

enum mosquitto__transport {
	mosq_t_invalid = 0,
	mosq_t_tcp = 1,
	mosq_t_ws = 2,
	mosq_t_sctp = 3
};


struct mosquitto__alias{
	char *topic;
	uint16_t alias;
};

struct session_expiry_list {
	struct mosquitto *context;
	struct session_expiry_list *prev;
	struct session_expiry_list *next;
};

struct mosquitto__packet{
	uint8_t *payload;
	struct mosquitto__packet *next;
	uint32_t remaining_mult;
	uint32_t remaining_length;
	uint32_t packet_length;
	uint32_t to_process;
	uint32_t pos;
	uint16_t mid;
	uint8_t command;
	int8_t remaining_count;
};

struct mosquitto_message_all{
	struct mosquitto_message_all *next;
	struct mosquitto_message_all *prev;
	mosquitto_property *properties;
	time_t timestamp;
	enum mosquitto_msg_state state;
	bool dup;
	struct mosquitto_message msg;
	uint32_t expiry_interval;
};

#ifdef WITH_TLS
enum mosquitto__keyform {
	mosq_k_pem = 0,
	mosq_k_engine = 1,
};
#endif

struct will_delay_list {
	struct mosquitto *context;
	struct will_delay_list *prev;
	struct will_delay_list *next;
};

struct mosquitto_msg_data{
#ifdef WITH_BROKER
	struct mosquitto_client_msg *inflight;
	struct mosquitto_client_msg *queued;
	long inflight_bytes;
	long inflight_bytes12;
	int inflight_count;
	int inflight_count12;
	long queued_bytes;
	long queued_bytes12;
	int queued_count;
	int queued_count12;
#else
	struct mosquitto_message_all *inflight;
	int queue_len;
#  ifdef WITH_THREADING
	pthread_mutex_t mutex;
#  endif
#endif
	int inflight_quota;
	uint16_t inflight_maximum;
};


struct mosquitto {
#if defined(WITH_BROKER) && defined(WITH_EPOLL)
	/// Epoll identifier; must remain the first member for event lookup.
	/// epoll 标识符，必须保持为结构体第一个成员以便事件查找。
	int ident;
#endif
	/// Network socket used by this MQTT connection.
	/// 此 MQTT 连接使用的网络套接字。
	mosq_sock_t sock;
#ifndef WITH_BROKER
	/// Read end of the local socket pair used to wake the client loop.
	/// 用于唤醒客户端循环的本地套接字对读端。
	mosq_sock_t sockpairR;
	/// Write end of the local socket pair used to wake the client loop.
	/// 用于唤醒客户端循环的本地套接字对写端。
	mosq_sock_t sockpairW;
#endif
	/// Maximum MQTT packet size accepted for this connection.
	/// 此连接允许接收的最大 MQTT 报文大小。
	uint32_t maximum_packet_size;
#if defined(__GLIBC__) && defined(WITH_ADNS)
	/// Asynchronous DNS request state for getaddrinfo_a.
	/// getaddrinfo_a 异步 DNS 请求状态。
	struct gaicb *adns;
#endif
	/// MQTT protocol version selected for this connection.
	/// 此连接选择的 MQTT 协议版本。
	enum mosquitto__protocol protocol;
	/// Peer network address or local bind address.
	/// 对端网络地址或本地绑定地址。
	char *address;
	/// MQTT client identifier.
	/// MQTT 客户端标识符。
	char *id;
	/// Authentication username.
	/// 认证用户名。
	char *username;
	/// Authentication password.
	/// 认证密码。
	char *password;
	/// MQTT keep-alive interval in seconds.
	/// MQTT 保活间隔，单位为秒。
	uint16_t keepalive;
	/// Last message identifier allocated for this client.
	/// 此客户端最近分配的消息标识符。
	uint16_t last_mid;
	/// Current MQTT connection state.
	/// 当前 MQTT 连接状态。
	enum mosquitto_client_state state;
	/// Time when the last inbound packet was received.
	/// 最近一次收到入站报文的时间。
	time_t last_msg_in;
	/// Scheduled time for the next outbound activity.
	/// 下一次出站活动的计划时间。
	time_t next_msg_out;
	/// Time at which the next keep-alive ping is due.
	/// 下一次保活 Ping 到期时间。
	time_t ping_t;
	/// Packet currently being received from the network.
	/// 当前正在从网络接收的报文。
	struct mosquitto__packet in_packet;
	/// Head packet currently being sent.
	/// 当前正在发送的报文。
	struct mosquitto__packet *current_out_packet;
	/// Head of the queued outbound packet list.
	/// 待发送报文队列的头节点。
	struct mosquitto__packet *out_packet;
	/// Last Will message configured for this client.
	/// 为此客户端配置的遗嘱消息。
	struct mosquitto_message_all *will;
	/// MQTT topic-alias mappings owned by this client.
	/// 此客户端拥有的 MQTT 主题别名映射。
	struct mosquitto__alias *aliases;
	/// Delayed Will list entry for this client.
	/// 此客户端在延迟遗嘱列表中的节点。
	struct will_delay_list *will_delay_entry;
	/// Number of topic aliases currently allocated.
	/// 当前分配的主题别名数量。
	int alias_count;
	/// Number of packets waiting in the outbound queue.
	/// 出站队列中等待发送的报文数量。
	int out_packet_count;
	/// Last Will delay interval in seconds.
	/// 遗嘱延迟间隔，单位为秒。
	uint32_t will_delay_interval;
	/// Absolute time when the delayed Will is sent.
	/// 发送延迟遗嘱的绝对时间。
	time_t will_delay_time;
#ifdef WITH_TLS
	/// Active TLS connection object.
	/// 当前 TLS 连接对象。
	SSL *ssl;
	/// TLS context used to create the active connection.
	/// 用于创建当前连接的 TLS 上下文。
	SSL_CTX *ssl_ctx;
#ifndef WITH_BROKER
	/// User-provided TLS context for libmosquitto.
	/// libmosquitto 使用的用户 TLS 上下文。
	SSL_CTX *user_ssl_ctx;
#endif
	/// CA certificate file used to verify peers.
	/// 用于验证对端的 CA 证书文件。
	char *tls_cafile;
	/// Directory containing trusted CA certificates.
	/// 包含可信 CA 证书的目录。
	char *tls_capath;
	/// Client certificate file presented during TLS handshake.
	/// TLS 握手期间提供的客户端证书文件。
	char *tls_certfile;
	/// Client private key file used during TLS handshake.
	/// TLS 握手期间使用的客户端私钥文件。
	char *tls_keyfile;
	/// Callback used to obtain a TLS private-key password.
	/// 用于获取 TLS 私钥密码的回调函数。
	int (*tls_pw_callback)(char *buf, int size, int rwflag, void *userdata);
	/// Requested TLS protocol version.
	/// 请求使用的 TLS 协议版本。
	char *tls_version;
	/// Requested TLS cipher list.
	/// 请求使用的 TLS 密码套件列表。
	char *tls_ciphers;
	/// Pre-shared key used for TLS-PSK authentication.
	/// TLS-PSK 认证使用的预共享密钥。
	char *tls_psk;
	/// Identity associated with the TLS-PSK.
	/// 与 TLS-PSK 关联的身份标识。
	char *tls_psk_identity;
	/// TLS engine name used for cryptographic operations.
	/// 用于加密操作的 TLS 引擎名称。
	char *tls_engine;
	/// SHA-1 password for the TLS engine key.
	/// TLS 引擎密钥的 SHA-1 密码。
	char *tls_engine_kpass_sha1;
	/// Application-Layer Protocol Negotiation protocol name.
	/// 应用层协议协商使用的协议名称。
	char *tls_alpn;
	/// TLS peer certificate verification requirement.
	/// TLS 对端证书验证要求。
	int tls_cert_reqs;
	/// Whether certificate verification errors are ignored.
	/// 是否忽略证书验证错误。
	bool tls_insecure;
	/// Whether default TLS context options were applied.
	/// 是否已应用默认 TLS 上下文选项。
	bool ssl_ctx_defaults;
	/// Whether OCSP certificate status is required.
	/// 是否要求 OCSP 证书状态检查。
	bool tls_ocsp_required;
	/// Whether platform-provided certificates are enabled.
	/// 是否启用平台提供的证书。
	bool tls_use_os_certs;
	/// Format of the configured TLS private key.
	/// 配置的 TLS 私钥格式。
	enum mosquitto__keyform tls_keyform;
#endif
	/// Whether the socket currently has data ready to write.
	/// 套接字当前是否有数据待写入。
	bool want_write;
#if defined(WITH_THREADING) && !defined(WITH_BROKER)
	/// Protects user callback state and invocation.
	/// 保护用户回调状态及其调用过程。
	pthread_mutex_t callback_mutex;
	/// Protects logging callback state.
	/// 保护日志回调状态。
	pthread_mutex_t log_callback_mutex;
	/// Protects message timestamp data.
	/// 保护消息时间戳数据。
	pthread_mutex_t msgtime_mutex;
	/// Protects the outbound packet queue.
	/// 保护出站报文队列。
	pthread_mutex_t out_packet_mutex;
	/// Protects the packet currently being sent.
	/// 保护当前正在发送的报文。
	pthread_mutex_t current_out_packet_mutex;
	/// Protects connection state transitions.
	/// 保护连接状态转换。
	pthread_mutex_t state_mutex;
	/// Protects message identifier allocation.
	/// 保护消息标识符分配。
	pthread_mutex_t mid_mutex;
	/// Thread running the libmosquitto network loop.
	/// 运行 libmosquitto 网络循环的线程。
	pthread_t thread_id;
#endif
	/// Whether the connection starts a new session.
	/// 连接是否启动新会话。
	bool clean_start;
	/// Absolute time when the stored session expires.
	/// 已保存会话的绝对过期时间。
	time_t session_expiry_time;
	/// Session expiry interval in seconds.
	/// 会话过期间隔，单位为秒。
	uint32_t session_expiry_interval;
#ifdef WITH_BROKER
	/// Whether this client is indexed by its client identifier.
	/// 此客户端是否已按客户端标识符建立索引。
	bool in_by_id;
	/// Whether packets for this client are being dropped.
	/// 是否正在丢弃此客户端的报文。
	bool is_dropping;
	/// Whether this connection represents a broker bridge.
	/// 此连接是否代表 Broker 桥接。
	bool is_bridge;
	/// Bridge configuration associated with this connection.
	/// 与此连接关联的桥接配置。
	struct mosquitto__bridge *bridge;
	/// Inbound message queue and flow-control state.
	/// 入站消息队列及流量控制状态。
	struct mosquitto_msg_data msgs_in;
	/// Outbound message queue and flow-control state.
	/// 出站消息队列及流量控制状态。
	struct mosquitto_msg_data msgs_out;
	/// Access-control entries assigned to this client.
	/// 分配给此客户端的访问控制条目。
	struct mosquitto__acl_user *acl_list;
	/// Listener that accepted this client connection.
	/// 接受此客户端连接的监听器。
	struct mosquitto__listener *listener;
	/// Tail of the queued outbound packet list.
	/// 待发送报文队列的尾节点。
	struct mosquitto__packet *out_packet_last;
	/// Subscription entries owned by this client.
	/// 此客户端拥有的订阅条目。
	struct mosquitto__client_sub **subs;
	/// Extended authentication method selected by the client.
	/// 客户端选择的扩展认证方法。
	char *auth_method;
	/// Number of subscriptions owned by this client.
	/// 此客户端拥有的订阅数量。
	int sub_count;
#  ifndef WITH_EPOLL
	/// Poll descriptor array index for this client.
	/// 此客户端在 poll 描述符数组中的索引。
	int pollfd_index;
#  endif
#  ifdef WITH_WEBSOCKETS
	/// WebSocket connection object.
	/// WebSocket 连接对象。
	struct lws *wsi;
#  endif
	/// Whether the WebSocket layer needs a write event.
	/// WebSocket 层是否需要写事件。
	bool ws_want_write;
	/// Whether the broker assigned the client identifier.
	/// 客户端标识符是否由 Broker 分配。
	bool assigned_id;
#else
#  ifdef WITH_SOCKS
	/// SOCKS5 proxy host name or address.
	/// SOCKS5 代理主机名或地址。
	char *socks5_host;
	/// SOCKS5 proxy port.
	/// SOCKS5 代理端口。
	uint16_t socks5_port;
	/// SOCKS5 proxy username.
	/// SOCKS5 代理用户名。
	char *socks5_username;
	/// SOCKS5 proxy password.
	/// SOCKS5 代理密码。
	char *socks5_password;
#  endif
	/// User-defined application context passed to callbacks.
	/// 传递给回调函数的用户自定义应用上下文。
	void *userdata;
	/// Whether execution is currently inside a user callback.
	/// 当前是否正在执行用户回调。
	bool in_callback;
	/// Inbound message queue and flow-control state.
	/// 入站消息队列及流量控制状态。
	struct mosquitto_msg_data msgs_in;
	/// Outbound message queue and flow-control state.
	/// 出站消息队列及流量控制状态。
	struct mosquitto_msg_data msgs_out;
	/// Callback invoked after an MQTT CONNECT result.
	/// MQTT CONNECT 结果产生后调用的回调。
	void (*on_connect)(struct mosquitto *, void *userdata, int rc);
	/// CONNECT callback that also reports negotiated flags.
	/// 同时报告协商标志的 CONNECT 回调。
	void (*on_connect_with_flags)(struct mosquitto *, void *userdata, int rc, int flags);
	/// MQTT v5 CONNECT callback with properties.
	/// 携带属性的 MQTT v5 CONNECT 回调。
	void (*on_connect_v5)(struct mosquitto *, void *userdata, int rc, int flags, const mosquitto_property *props);
	/// Callback invoked after an MQTT disconnect.
	/// MQTT 断开连接后调用的回调。
	void (*on_disconnect)(struct mosquitto *, void *userdata, int rc);
	/// MQTT v5 disconnect callback with properties.
	/// 携带属性的 MQTT v5 断开回调。
	void (*on_disconnect_v5)(struct mosquitto *, void *userdata, int rc, const mosquitto_property *props);
	/// Callback invoked after a publish completes.
	/// 发布操作完成后调用的回调。
	void (*on_publish)(struct mosquitto *, void *userdata, int mid);
	/// MQTT v5 publish callback with reason and properties.
	/// 携带原因码和属性的 MQTT v5 发布回调。
	void (*on_publish_v5)(struct mosquitto *, void *userdata, int mid, int reason_code, const mosquitto_property *props);
	/// Callback invoked when an incoming message is delivered.
	/// 收到并交付消息时调用的回调。
	void (*on_message)(struct mosquitto *, void *userdata, const struct mosquitto_message *message);
	/// MQTT v5 message callback with properties.
	/// 携带属性的 MQTT v5 消息回调。
	void (*on_message_v5)(struct mosquitto *, void *userdata, const struct mosquitto_message *message, const mosquitto_property *props);
	/// Callback invoked after a subscribe response.
	/// 收到订阅响应后调用的回调。
	void (*on_subscribe)(struct mosquitto *, void *userdata, int mid, int qos_count, const int *granted_qos);
	/// MQTT v5 subscribe callback with properties.
	/// 携带属性的 MQTT v5 订阅回调。
	void (*on_subscribe_v5)(struct mosquitto *, void *userdata, int mid, int qos_count, const int *granted_qos, const mosquitto_property *props);
	/// Callback invoked after an unsubscribe response.
	/// 收到取消订阅响应后调用的回调。
	void (*on_unsubscribe)(struct mosquitto *, void *userdata, int mid);
	/// MQTT v5 unsubscribe callback with properties.
	/// 携带属性的 MQTT v5 取消订阅回调。
	void (*on_unsubscribe_v5)(struct mosquitto *, void *userdata, int mid, const mosquitto_property *props);
	/// Callback receiving library log messages.
	/// 接收库日志消息的回调。
	void (*on_log)(struct mosquitto *, void *userdata, int level, const char *str);
	/*void (*on_error)();*/
	/// Remote MQTT broker host name or address.
	/// 远程 MQTT Broker 主机名或地址。
	char *host;
	/// Remote MQTT broker port.
	/// 远程 MQTT Broker 端口。
	uint16_t port;
	/// Local address used for the outgoing connection.
	/// 出站连接使用的本地地址。
	char *bind_address;
	/// Number of reconnect attempts already made.
	/// 已经进行的重连尝试次数。
	unsigned int reconnects;
	/// Current reconnect delay in seconds.
	/// 当前重连延迟，单位为秒。
	unsigned int reconnect_delay;
	/// Maximum reconnect delay in seconds.
	/// 最大重连延迟，单位为秒。
	unsigned int reconnect_delay_max;
	/// Whether reconnect delay uses exponential backoff.
	/// 重连延迟是否使用指数退避。
	bool reconnect_exponential_backoff;
	/// Whether the application requested a disconnect.
	/// 应用是否请求断开连接。
	bool request_disconnect;
	/// Threading mode used by the client loop.
	/// 客户端循环使用的线程模式。
	char threaded;
	/// Tail of the queued outbound packet list.
	/// 待发送报文队列的尾节点。
	struct mosquitto__packet *out_packet_last;
	/// MQTT properties included in the CONNECT packet.
	/// CONNECT 报文中包含的 MQTT 属性。
	mosquitto_property *connect_properties;
#  ifdef WITH_SRV
	/// c-ares channel used for SRV record lookup.
	/// 用于查询 SRV 记录的 c-ares 通道。
	ares_channel achan;
#  endif
#endif
	/// Highest MQTT QoS supported by this connection.
	/// 此连接支持的最高 MQTT QoS。
	uint8_t max_qos;
	/// Whether retained messages are supported.
	/// 是否支持保留消息。
	uint8_t retain_available;
	/// Whether TCP_NODELAY is enabled for this connection.
	/// 此连接是否启用 TCP_NODELAY。
	bool tcp_nodelay;

#ifdef WITH_BROKER
	/// Hash-table handle indexed by client identifier.
	/// 按客户端标识符索引的哈希表句柄。
	UT_hash_handle hh_id;
	/// Hash-table handle indexed by socket.
	/// 按套接字索引的哈希表句柄。
	UT_hash_handle hh_sock;
	/// Next client in the broker's deferred-free list.
	/// Broker 延迟释放列表中的下一个客户端。
	struct mosquitto *for_free_next;
	/// Session-expiry list entry for this client.
	/// 此客户端在会话过期列表中的节点。
	struct session_expiry_list *expiry_list_item;
	/// Remote TCP port of the client connection.
	/// 客户端连接的远程 TCP 端口。
	uint16_t remote_port;
#endif
	/// Event mask registered for this connection.
	/// 为此连接注册的事件掩码。
	uint32_t events;

	/// Index of the authentication plugin currently handling the client.
	/// 当前处理此客户端的认证插件索引。
	uint64_t auth_plugins_idx;
};

#define STREMPTY(str) (str[0] == '\0')

void do_client_disconnect(struct mosquitto *mosq, int reason_code, const mosquitto_property *properties);

#endif

