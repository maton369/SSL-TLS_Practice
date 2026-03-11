#include <stdio.h>      // 標準入出力を扱うためのヘッダ。
                        // printf, perror などの基本的な入出力関数を使うときに必要になる。

#include <unistd.h>     // UNIX 系 OS の基本システムコールを扱うためのヘッダ。
                        // close, read, write などの低レイヤな入出力やプロセス制御で使われる。

#include <string.h>     // 文字列処理用のヘッダ。
                        // memset, memcpy, strlen など、バッファ初期化や文字列操作でよく使う。

#include <stdbool.h>    // C 言語で bool, true, false を使えるようにするヘッダ。
                        // 「サーバかクライアントか」のような二値フラグを分かりやすく表現できる。

#include <sys/socket.h> // ソケット API の基本を提供するヘッダ。
                        // socket, bind, listen, accept, connect などの通信用システムコールを使うのに必要。

#include <arpa/inet.h>  // IP アドレスやポート番号の変換を扱うヘッダ。
                        // htons, htonl, inet_pton, inet_ntop など、
                        // ネットワークバイトオーダと文字列表現の変換で使う。

#include <openssl/ssl.h> // OpenSSL の SSL/TLS 機能本体を扱うヘッダ。
                         // SSL, SSL_CTX, SSL_new, SSL_connect, SSL_accept など、
                         // TLS 通信を行うための主要 API を宣言している。

#include <openssl/err.h> // OpenSSL のエラー処理用ヘッダ。
                         // ERR_print_errors_fp などを使って、
                         // SSL/TLS 処理中に発生したエラーの詳細を確認できる。


/*
 * create_socket:
 * ソケットを作成するための関数プロトタイプ。
 *
 * 引数:
 *   isServer
 *     true ならサーバ用ソケットとして使う想定。
 *     false ならクライアント用ソケットとして使う想定。
 *
 *   socktype
 *     ソケットの種類を指定する。
 *     典型例:
 *       SOCK_STREAM : TCP 用
 *       SOCK_DGRAM  : UDP 用
 *
 *   family
 *     アドレスファミリを指定する。
 *     典型例:
 *       AF_INET   : IPv4
 *       AF_INET6  : IPv6
 *
 * 戻り値:
 *   正常時:
 *     作成されたソケットのファイルディスクリプタ。
 *
 *   異常時:
 *     通常は -1 などのエラー値を返す設計が多い。
 *
 * 役割:
 *   この関数は単に socket() を呼ぶだけでなく、
 *   実装次第では以下のような初期化もまとめて行える。
 *
 *   サーバ側:
 *     1. socket() でソケット生成
 *     2. bind() でアドレス/ポートへ割り当て
 *     3. listen() で待受状態へ移行
 *
 *   クライアント側:
 *     1. socket() でソケット生成
 *     2. connect() でサーバへ接続
 *
 * つまり、この `isServer` フラグによって
 * 「待ち受け側の初期化」か「接続側の初期化」かを分岐させる設計が想定される。
 *
 * SSL/TLS との関係:
 *   TLS は TCP ソケットの上で動くため、
 *   まずこの関数で通常のソケット通信路を作り、
 *   その後に SSL オブジェクトをそのソケットへ関連付ける流れになる。
 */
int create_socket(bool isServer, int socktype, int family);


/*
 * create_context:
 * SSL/TLS 通信のための SSL_CTX（コンテキスト）を作成する関数プロトタイプ。
 *
 * 引数:
 *   isServer
 *     true ならサーバ用の SSL_CTX を作る。
 *     false ならクライアント用の SSL_CTX を作る。
 *
 * 戻り値:
 *   正常時:
 *     初期化済みの SSL_CTX 構造体へのポインタ。
 *
 *   異常時:
 *     NULL を返す設計が一般的。
 *
 * SSL_CTX とは:
 *   OpenSSL における「TLS 通信の設定一式」を保持する大元のオブジェクトである。
 *   ここには、たとえば次のような情報を設定することが多い。
 *
 *   - 使用する TLS メソッド（TLS_server_method, TLS_client_method など）
 *   - 使用可能な TLS バージョン
 *   - 証明書ファイル
 *   - 秘密鍵ファイル
 *   - 信頼する CA 証明書
 *   - 検証ポリシー
 *   - Cipher Suite / TLS 1.3 cipher の設定
 *
 * サーバ側とクライアント側の違い:
 *
 *   サーバ側:
 *     - 自分の証明書と秘密鍵をロードすることが多い
 *     - クライアント認証を要求するか設定する場合もある
 *
 *   クライアント側:
 *     - サーバ証明書を検証するための CA を読み込むことが多い
 *     - ホスト名検証や証明書検証モードを設定する場合がある
 *
 * 通信全体の流れの中での位置づけ:
 *
 *   1. SSL ライブラリ初期化
 *   2. create_context() で TLS 設定の土台を作る
 *   3. create_socket() で TCP ソケットを作る
 *   4. SSL_new() で個別接続用 SSL オブジェクトを作る
 *   5. SSL_set_fd() でソケットと SSL を結び付ける
 *   6. サーバなら SSL_accept(), クライアントなら SSL_connect()
 *   7. SSL_read / SSL_write で暗号化通信を行う
 *
 * つまり SSL_CTX は、
 * 「個々の接続の前に一度用意する、TLS 設定の共通基盤」
 * と考えると理解しやすい。
 */
SSL_CTX* create_context(bool isServer);
