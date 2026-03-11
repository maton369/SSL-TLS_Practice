#include <netdb.h>   // getaddrinfo(), freeaddrinfo() など、ホスト名解決やアドレス情報取得に使うヘッダ。
                    // クライアントは "booktls-server" というホスト名から接続先 IP を調べるために必要になる。

#include "common.h" // 共通ヘッダ。
                    // これまでの流れから、おそらく以下を含んでいる。
                    // - 標準 C ライブラリ系 include
                    // - OpenSSL 関連ヘッダ
                    // - create_socket(), create_context() の宣言
                    // - exit(EXIT_FAILURE) などに必要な宣言
                    //
                    // このクライアント実装は common.c 側の
                    // 「ソケット生成」「SSL_CTX 生成」などの共通関数を利用している。


/* サーバのホスト名 */
static const char* server_host = "booktls-server";
// 接続先サーバのホスト名。
// Docker Compose のネットワーク内では、サービス名や container_name を
// DNS 名前解決できることが多く、ここでは "booktls-server" に接続する想定である。
// TLS のホスト名検証でもこの文字列を使うため、単なる接続先名ではなく
// 「証明書検証対象のホスト名」という意味も持つ。


/* サーバのポート番号(commom.c) */
extern const int server_port;
// common.c 側で定義されているサーバポート番号を参照する。
// extern を付けることで、ここでは定義せず「別の翻訳単位にある変数」を使うことを示す。
// コメントの "commom.c" はたぶん "common.c" の typo である。
// たとえば 443 や 10443 がここに入っている想定である。


/* CA証明書のパス */
#define CA_CERT "./certs/ca.pem"
// サーバ証明書を検証するために使う CA 証明書ファイル。
// クライアントは TLS ハンドシェイク時にサーバから送られてくる証明書チェーンを検証する。
// そのとき、「何を信頼の起点にするか」がこの CA 証明書である。
//
// 学習用の閉じた環境では、自前 CA で server.crt に署名しているため、
// システム標準 CA ストアではなく、このローカル CA ファイルを明示的に読み込む必要がある。


/* エコーバックするメッセージ一覧 */
static const char* txmsg_full  = "full handshake test\n";
// フルハンドシェイク確認用に送るメッセージ。
// 通信経路が正しく確立されたかを確認するアプリケーションデータとして使う。

static const char* txmsg_resum = "session resumption test\n";
// セッション再開 (resumption) の確認用メッセージ。
// 1回目の接続でセッション情報を得て、2回目の接続でそれを再利用できるかを試す。

static const char* txmsg_hrr1  = "HRR test\n";
// Hello Retry Request の確認用メッセージ。
// グループ交渉 (key share / supported groups) を意図的に調整し、
// サーバが HRR を返すようなシナリオを試す用途。

static const char* txmsg_early = "early data test\n";
// early data (0-RTT) の確認用メッセージ。
// TLS 1.3 の 0-RTT と、その後の通常アプリケーションデータを区別して見るために使う。


static SSL_SESSION *session = NULL;
// セッション再開や early data で再利用するための SSL_SESSION ポインタ。
//
// TLS 1.3 では、1回目の接続後にサーバから Session Ticket が送られ、
// それに基づいて次回接続時に resumption が可能になる。
// この変数は、その ticket に対応するセッション情報を保持する役割を持つ。
//
// グローバルに置いているため、
//   full_handshake()
//   session_resumption()
//   early_data()
// のような複数関数間で共有しやすい。
// ただし実運用の大規模コードでは、グローバル状態は管理が難しくなるため、
// コンテキスト構造体へまとめる設計の方が保守しやすいことが多い。


void configure_client_context(SSL_CTX *ctx);
// クライアント用 SSL_CTX の設定関数。
// CA 読み込み、検証設定、TLS バージョン制限などをまとめて行う。

void full_handshake(void);
// 通常のフル TLS 1.3 ハンドシェイクを行うサンプル関数。

static int new_session_cb(SSL *s, SSL_SESSION *sess);
// 新しいセッションが得られたときに OpenSSL から呼ばれるコールバック。
// 主に session resumption / early data のために Session Ticket を保持する。

void session_resumption(void);
// セッション再開を試すサンプル関数。
// 初回接続で得た session を次回接続に流用し、resumption を観察する。

void hello_retry_request(void);
// Hello Retry Request (HRR) を試すサンプル関数。
// クライアントの supported groups を制限し、サーバから HRR を誘発する。

void early_data(void);
// TLS 1.3 early data (0-RTT) を試すサンプル関数。
// resumption で得た session ticket を元に、ハンドシェイク完了前にアプリケーションデータを送る。


/* クライアントコンテキストの設定関数 */
void configure_client_context(SSL_CTX *ctx)
{
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // サーバ証明書を検証するように SSL_CTX を設定する。
    //
    // SSL_VERIFY_PEER
    //   相手証明書を検証するモード。
    //   クライアントとしては非常に重要で、
    //   これをしないと「暗号化はされるが相手の正当性を確認しない」状態になりうる。
    //
    // 第3引数 NULL
    //   独自検証コールバックは使わず、OpenSSL 標準の検証ロジックを使う。
    //
    // つまり、ここでは
    //   「TLS ハンドシェイク時に、サーバ証明書を信頼済み CA で検証せよ」
    // という基本方針を設定している。

    if (!SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL)) {
        // 信頼する CA 証明書を読み込む。
        //
        // 第2引数 CA_CERT
        //   信頼の起点となる CA ファイルを指定する。
        //
        // 第3引数 NULL
        //   ディレクトリ単位ではなく、単一ファイル指定であることを表す。
        //
        // これにより、サーバが提示した証明書チェーンを
        // "./certs/ca.pem" を信頼ルートとして検証できるようになる。
        //
        // 学習環境では自作 CA を使っているため、システム標準の trust store ではなく
        // このローカル CA を明示的に読み込むのが自然である。
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* サポートする最低のバージョンをTLS1.3に */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    // サポートする最小 TLS バージョンを TLS 1.3 に制限する。
    //
    // これにより、このクライアントは TLS 1.2 以下へフォールバックしない。
    // 今回のサンプルは
    //   - full handshake
    //   - session resumption
    //   - Hello Retry Request
    //   - early data (0-RTT)
    // といった TLS 1.3 特有の動作を学ぶことが目的なので、
    // バージョンを 1.3 へ固定しているのは理にかなっている。
    //
    // もしサーバが TLS 1.2 までしか話せない場合は接続失敗する。
}


/* フルハンドシェイクのサンプル */
void full_handshake(void)
{
    SSL_CTX *ssl_ctx = NULL;  // TLS 設定全体を保持するコンテキスト。
    SSL *ssl = NULL;          // 1 接続ぶんの TLS セッションオブジェクト。

    int result;               // SSL_write() などの戻り値を受けるための変数。
    int err;                  // getaddrinfo() などのエラーコード保持用。

    int client_skt = -1;      // TCP ソケット FD。未作成を -1 で表す。
    char server_port_str[16]; // getaddrinfo() に渡すためのポート番号文字列。

    /* 送信バッファ */
    char txbuf[64];           // アプリケーションデータ送信用バッファ。
    size_t txcap = sizeof(txbuf); // バッファ容量。
    int txlen;                // 実際に送るデータ長。

    /* 受信バッファ */
    char rxbuf[128];          // サーバからの応答受信用バッファ。
    size_t rxcap = sizeof(rxbuf); // 受信バッファ容量。
    int rxlen;                // 実際に受信した長さ。

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    // getaddrinfo() 用のヒント構造体をゼロ初期化する。
    // 未使用フィールドにゴミ値が入らないようにするため重要。

    ssl_ctx = create_context(false);
    // クライアント用 SSL_CTX を生成する。
    // false を渡しているので common.c 側では TLS_client_method() が選ばれる想定。

    printf("full handshake start\n\n");

    configure_client_context(ssl_ctx);
    // クライアント用 SSL_CTX に
    // - 証明書検証を有効化
    // - CA 読み込み
    // - TLS 1.3 制限
    // を適用する。

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    // IPv4 + TCP を指定する。
    // 今回のクライアントは IPv4/TCP に限定している。
    //
    // したがって、名前解決結果としては IPv4 アドレスのみを期待する。
    // IPv6 にも対応したければ AF_UNSPEC にして複数候補を試す設計もあり得る。

    do {
        // do { ... } while(false) は、途中で break により抜けやすくするための
        // C で時々使われるエラーハンドリングパターン。
        //
        // 深い if ネストを避けながら、
        // 途中失敗時に後始末処理へ流しやすくする。

        client_skt = create_socket(false, hints.ai_family, hints.ai_socktype);
        // クライアント用の TCP ソケットを生成する。
        // false なので bind/listen までは行わず、単に socket() 相当を行う想定。

        sprintf(server_port_str, "%d", server_port);
        // getaddrinfo() はポート番号を文字列で受けるため、整数ポート番号を文字列化する。
        //
        // 注意:
        // sprintf はバッファ長制限なしなので、実運用では snprintf の方が安全である。
        // ただし port 番号は短く、server_port_str も十分大きいので、
        // 学習用途としては実害は出にくい。

        if ((err = getaddrinfo(server_host, server_port_str, &hints, &res)) != 0) {
            perror("getaddrinfo failed");
            // 注意点:
            // getaddrinfo() は errno ではなく独自の戻り値 err を返すので、
            // 本来は perror() より gai_strerror(err) を使う方が正確である。
            //
            // つまりレビュー観点では、
            //   perror("getaddrinfo failed");
            // ではなく
            //   fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(err));
            // が望ましい。
            break;
        }

        if (connect(client_skt, res->ai_addr,  res->ai_addrlen) != 0) {
            // TCP レベルでサーバへ接続する。
            //
            // ここではまだ TLS は始まっておらず、単なる TCP 3-way handshake の段階である。
            //
            // この後、
            //   SSL_new()
            //   SSL_set_fd()
            //   SSL_connect()
            // を行うことで、TCP の上に TLS を重ねる。
            perror("Unable to TCP connect to server");
            break;
        } else {
            printf("TCP connection to server successful\n");
        }
        freeaddrinfo(res);
        // getaddrinfo() が確保したアドレス情報リストを解放する。
        // これを忘れるとメモリリークになる。

        ssl = SSL_new(ssl_ctx);
        // 1 接続ごとの SSL オブジェクトを生成する。
        //
        // SSL_CTX が「設定のひな形」だとすると、
        // SSL は「実際に今このソケット上で行う TLS 通信そのもの」に対応する。

        SSL_set_fd(ssl, client_skt);
        // 生成した SSL オブジェクトを TCP ソケットへ関連付ける。
        //
        // ここでようやく
        //   TLS over TCP
        // の土台が完成する。

        SSL_set1_host(ssl, server_host);
        // ホスト名検証用の期待ホスト名を設定する。
        //
        // これは非常に重要で、サーバ証明書の SAN / CN に
        // "booktls-server" が含まれているかを検証するために使われる。
        //
        // CA 検証だけでは「信頼できる誰かの証明書」かどうかしか分からない。
        // その証明書が本当に接続先ホスト名に対応しているかを確認するのが
        // ホスト名検証である。

        SSL_set_tlsext_host_name(ssl, server_host);
        // SNI (Server Name Indication) を設定する。
        //
        // クライアントが TLS ClientHello の中で
        // 「どのホスト名に接続したいか」をサーバへ伝える拡張である。
        //
        // 1 台のサーバが複数ドメインを持つ virtual hosting で重要になる。
        // 学習環境でも、証明書切り替え挙動や SNI の概念を理解するために入れておく価値がある。

        if (SSL_connect(ssl) == 1) {
            // クライアントとして TLS ハンドシェイクを実行する。
            //
            // ここで行われるのは概念的に次の処理である。
            //
            //   ClientHello
            //      ↓
            //   ServerHello
            //      ↓
            //   EncryptedExtensions
            //      ↓
            //   Certificate
            //      ↓
            //   CertificateVerify
            //      ↓
            //   Finished
            //
            // その後、クライアントも Finished を送り、TLS 1.3 の暗号化通信路が完成する。

            printf("SSL connection to server successful\n\n");

            txlen = strlen(txmsg_full);
            // 送信する文字列長を求める。

            memset(txbuf, 0x00, txcap);
            // 送信バッファ全体をゼロクリアする。
            // 今回は単に学習用の見通しを良くする意味合いが強い。

            memcpy(txbuf, txmsg_full, txlen);
            // 送信メッセージを送信バッファへコピーする。
            // バッファにコピーしてから送ることで、
            // 実際に SSL_write() が扱うデータ領域を明確にしている。

            if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
                // TLS アプリケーションデータとしてサーバへ送信する。
                //
                // TCP write() ではなく SSL_write() を使うことで、
                // OpenSSL が暗号化・レコード分割・整合性保護を行ったうえで送信される。
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            rxlen = SSL_read(ssl, rxbuf, rxcap);
            // サーバから TLS アプリケーションデータを受信する。
            //
            // OpenSSL が内部で復号・認証タグ検証などを行い、
            // その結果の平文データが rxbuf に入る。
            if (rxlen <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            } else {
                rxbuf[rxlen] = 0;
                // C 文字列として扱うため終端 NUL を付ける。
                //
                // 注意:
                // rxbuf のサイズが 128 なのに SSL_read の長さを rxcap (= 128) まで許しているため、
                // もし 128 バイトちょうど受信した場合は rxbuf[128] = 0 が範囲外書き込みになる。
                // したがって実運用では
                //   SSL_read(ssl, rxbuf, rxcap - 1)
                // のように 1 バイト余らせる方が安全である。
                printf("Received: %s", rxbuf);
            }

            printf("Client exiting...\n");
        } else {

            printf("SSL connection to server failed\n\n");

            ERR_print_errors_fp(stderr);
            // TLS ハンドシェイク失敗時の詳細を表示する。
            //
            // 典型的な失敗要因:
            // - 証明書検証失敗
            // - ホスト名不一致
            // - TLS バージョン不一致
            // - cipher / group 不一致
        }
    } while(false);

    if (ssl != NULL) {
        SSL_shutdown(ssl);
        // TLS close_notify を送って正常終了を試みる。
        //
        // これにより「ただ TCP を切った」のではなく、
        // TLS レイヤでも通信終了を通知できる。
        SSL_free(ssl);
        // SSL オブジェクトを解放する。
    }

    SSL_CTX_free(ssl_ctx);
    // SSL_CTX を解放する。
    // 接続単位ではなくコンテキスト単位の後始末。

    if (client_skt != -1) {
        close(client_skt);
        // TCP ソケットを閉じる。
    }
}


/* 新規セッションのコールバック */
static int new_session_cb(SSL *s, SSL_SESSION *sess)
{
    if (session == NULL) {
        SSL_SESSION_up_ref(sess);
        // OpenSSL から渡された SSL_SESSION をこのプログラム側でも保持するため、
        // 参照カウントを増やす。
        //
        // SSL_SESSION は OpenSSL 内部所有のままだと寿命管理が難しいため、
        // 保持したい場合は up_ref() してから自前の変数へ格納するのが正しい。
        session = sess;
    }

    if (SSL_version(s) == TLS1_3_VERSION) {
        printf("Session Ticket arrived\n");
        // TLS 1.3 では Session Ticket が到着すると、
        // それを元に次回接続で resumption や early data が可能になる。
        //
        // この表示は「新しい再開可能セッションが得られた」ことの確認になる。
    }

    return 0;
    // OpenSSL の新規セッションコールバック。
    // 返り値の意味は API に依存するが、ここでは追加処理後に 0 を返している。
}


/* セッション再開のサンプル */
void session_resumption(void)
{
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int result;
    int err;
    int count = 0;
    // count で 2 回接続する。
    // 1回目: フルハンドシェイクで session ticket を得る
    // 2回目: session を再利用して resumption を試す

    int client_skt = -1;
    char server_port_str[16];

    char txbuf[64];
    size_t txcap = sizeof(txbuf);
    int txlen;

    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    session = NULL;
    // 前回までのグローバル session をクリアしておく。
    // これにより、今回のシナリオをまっさらな状態から始められる。

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));

    ssl_ctx = create_context(false);

    printf("session resumption start\n\n");

    configure_client_context(ssl_ctx);

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    do {
        client_skt = create_socket(false, hints.ai_family, hints.ai_socktype);

        sprintf(server_port_str, "%d", server_port);
        if ((err = getaddrinfo(server_host, server_port_str, &hints, &res)) != 0) {
            perror("getaddrinfo failed");
            break;
        }

        if (connect(client_skt, res->ai_addr,  res->ai_addrlen) != 0) {
            perror("Unable to TCP connect to server");
            break;
        } else {
            printf("TCP connection to server successful\n");
        }
        freeaddrinfo(res);

        SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_CLIENT
                                        | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        // クライアント側セッションキャッシュの挙動を設定する。
        //
        // SSL_SESS_CACHE_CLIENT
        //   クライアントとしてセッションキャッシュ機能を使う。
        //
        // SSL_SESS_CACHE_NO_INTERNAL_STORE
        //   OpenSSL 内部の自動保存を使わず、自前で管理する。
        //
        // 今回はグローバル変数 session に明示的に保存したいため、
        // 内部ストアをオフにしている。

        SSL_CTX_sess_set_new_cb(ssl_ctx, new_session_cb);
        // 新しいセッションが得られたときに呼ばれるコールバックを登録する。
        // ここで Session Ticket を受け取り、session へ保存する。

        ssl = SSL_new(ssl_ctx);

        if (session != NULL){
            SSL_set_session(ssl, session);
            // すでに保存済みセッションがある場合、
            // 次の接続でそのセッションを使うよう SSL オブジェクトへ設定する。
            //
            // これにより、2回目の接続では resumption が試みられる。
            printf("set session ticket\n");
        }

        SSL_set_fd(ssl, client_skt);

        SSL_set1_host(ssl, server_host);
        SSL_set_tlsext_host_name(ssl, server_host);

        if (SSL_connect(ssl) == 1) {

            printf("SSL connection to server successful count=%d\n\n", count);
            // count=0 なら通常フルハンドシェイク
            // count=1 なら resumption を期待する接続

            txlen = strlen(txmsg_resum);
            memset(txbuf, 0x00, txcap);
            memcpy(txbuf, txmsg_resum, txlen);

            if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            rxlen = SSL_read(ssl, rxbuf, rxcap);
            if (rxlen <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            } else {
                rxbuf[rxlen] = 0;
                printf("Received: %s", rxbuf);
            }

            printf("Client exiting...\n");
        } else {

            printf("SSL connection to server failed\n\n");

            ERR_print_errors_fp(stderr);
        }

        if (ssl != NULL) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = NULL;
            // ループの次回反復で古い SSL を誤再利用しないよう明示的に NULL に戻すとより安全。
        }

        if (client_skt != -1) {
            close(client_skt);
            client_skt = -1;
        }
        count++;
    } while(count <= 1);
    // count=0,1 の 2 回回る。
    //
    // アルゴリズム的には:
    //   1回目: ticket を取得
    //   2回目: ticket を使って再開を試す
    //
    // という TLS 1.3 resumption の典型例である。

    SSL_SESSION_free(session);
    // up_ref して保持していたセッションを解放する。
    // 参照カウント管理の対になる後始末である。

    ssl = NULL;
    session = NULL;

    SSL_CTX_free(ssl_ctx);
}


/* Hello Retry Requestのサンプル */
void hello_retry_request(void)
{
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int result;
    int err;

    int client_skt = -1;
    char server_port_str[16];

    /* 送信バッファ */
    char txbuf[64];
    size_t txcap = sizeof(txbuf);
    int txlen;

    /* 受信バッファ */
    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));

    ssl_ctx = create_context(false);

    printf("Hello Retry Request start\n\n");

    configure_client_context(ssl_ctx);

    /* supported_groupsをP-256とP-521に限定する */
    SSL_CTX_set1_groups_list(ssl_ctx, "P-256:P-521");
    // クライアントがサポートすると宣言する楕円曲線グループを限定する。
    //
    // TLS 1.3 では key share / supported groups の交渉が行われる。
    // サーバが要求するグループとクライアントの初回送信 key share が合わない場合、
    // サーバは Hello Retry Request (HRR) を返すことがある。
    //
    // ここではグループをあえて限定することで、
    // HRR を観察しやすいシナリオを作ろうとしている。

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    do {
        client_skt = create_socket(false, hints.ai_family, hints.ai_socktype);

        sprintf(server_port_str, "%d", server_port);
        if ((err = getaddrinfo(server_host, server_port_str, &hints, &res)) != 0) {
            perror("getaddrinfo failed");
            break;
        }

        if (connect(client_skt, res->ai_addr,  res->ai_addrlen) != 0) {
            perror("Unable to TCP connect to server");
            break;
        } else {
            printf("TCP connection to server successful\n");
        }
        freeaddrinfo(res);

        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_skt);

        SSL_set1_host(ssl, server_host);
        SSL_set_tlsext_host_name(ssl, server_host);

        if (SSL_connect(ssl) == 1) {

            printf("SSL connection to server successful\n\n");
            // 成功時、内部的には
            //   ClientHello
            //     ↓
            //   HelloRetryRequest (必要なら)
            //     ↓
            //   2回目の ClientHello
            //     ↓
            //   ServerHello ...
            // のような流れを経ている。
            //
            // 実際に HRR が発生したかは、パケットキャプチャや OpenSSL ログで観察するのが有効。

            txlen = strlen(txmsg_hrr1);
            memset(txbuf, 0x00, txcap);
            memcpy(txbuf, txmsg_hrr1, txlen);

            if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            rxlen = SSL_read(ssl, rxbuf, rxcap);
            if (rxlen <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            } else {
                rxbuf[rxlen] = 0;
                printf("Received: %s", rxbuf);
            }

            printf("Client exiting...\n");
        } else {

            printf("SSL connection to server failed\n\n");

            ERR_print_errors_fp(stderr);
        }
    } while(false);

    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1) {
        close(client_skt);
    }
}


/* early data(0-RTT)のサンプル */
void early_data(void)
{
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int result;
    int err;
    int count = 0;
    // 2 回接続する。
    // 1 回目で session ticket を得る。
    // 2 回目で 0-RTT early data を送る。

    int client_skt = -1;
    char server_port_str[16];

    char txbuf[64];
    size_t txcap = sizeof(txbuf);
    int txlen;

    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    session = NULL;
    // early data は session resumption 前提なので、まず新しいセッション情報を取りに行く。

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));

    ssl_ctx = create_context(false);

    printf("early data start\n\n");

    configure_client_context(ssl_ctx);

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    do {
        client_skt = create_socket(false, hints.ai_family, hints.ai_socktype);

        sprintf(server_port_str, "%d", server_port);
        if ((err = getaddrinfo(server_host, server_port_str, &hints, &res)) != 0) {
            perror("getaddrinfo failed");
            break;
        }

        if (connect(client_skt, res->ai_addr,  res->ai_addrlen) != 0) {
            perror("Unable to TCP connect to server");
            break;
        } else {
            printf("TCP connection to server successful\n");
        }
        freeaddrinfo(res);

        SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_CLIENT
                                        | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(ssl_ctx, new_session_cb);
        // session_resumption() と同様に、
        // session ticket を自前で保持するための設定を行う。

        ssl = SSL_new(ssl_ctx);

        if (session != NULL){
            SSL_set_session(ssl, session);
            // 2回目接続では、得ておいたセッションを流用する。
            printf("set session\n");
        }

        SSL_set_fd(ssl, client_skt);

        SSL_set1_host(ssl, server_host);
        SSL_set_tlsext_host_name(ssl, server_host);

        /* early_dataの送信 */
        if ((session != NULL) && SSL_SESSION_get_max_early_data(session) > 0) {
            // session があり、かつそのセッションが early data を許可しているなら
            // 0-RTT データ送信を試みる。
            //
            // TLS 1.3 では、PSK/resumption に基づいて
            // ハンドシェイク完了前にアプリケーションデータを送れる。
            // これが early data (0-RTT) である。
            //
            // ただし replay 攻撃の性質などにより制約があり、
            // サーバが受け付ける内容には注意が必要である。

            size_t writtenbytes;
            char cbuf[] = "this_is_early_data";
            // 実際に 0-RTT で送るデータ。
            // 通常のアプリケーションデータ送信とは別に、ハンドシェイク前倒しで送信する。

            while (!SSL_write_early_data(ssl, cbuf, strlen(cbuf), &writtenbytes)) {
                // early data 送信を試みる。
                //
                // OpenSSL は I/O 状態に応じて
                //   WANT_READ
                //   WANT_WRITE
                //   WANT_ASYNC
                // を返すことがあるため、ループで再試行している。
                //
                // ここでは busy waiting で再試行する簡易実装になっている。
                switch (SSL_get_error(ssl, 0)) {
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_ASYNC:
                case SSL_ERROR_WANT_READ:
                    /* Just keep trying - busy waiting */
                    continue;
                default:
                    printf("Error writing early data\n");
                    ERR_print_errors_fp(stderr);
                }
                printf("send early data %ld bytes\n", writtenbytes);
                // 注意:
                // この printf は default 節のあとにあるため、
                // 現状だとエラー時以外の成功ログとしては少し不自然な位置にある。
                // レビュー観点では、ループを抜けたあとに表示した方が意図が明確になる。
            }
            
        }

        if (SSL_connect(ssl) == 1) {
            // early data を送った後、通常の TLS 1.3 ハンドシェイクを完了させる。
            //
            // 0-RTT の流れは概念的には
            //   ClientHello + early data
            //      ↓
            //   ServerHello ...
            //      ↓
            //   handshake 完了
            // である。
            //
            // 0-RTT は「完全な接続確立前の先行送信」であり、
            // この SSL_connect() が成功して初めて本格的な TLS セッションが成立する。

            printf("SSL connection to server successful count=%d\n\n", count);

            txlen = strlen(txmsg_early);
            memset(txbuf, 0x00, txcap);
            memcpy(txbuf, txmsg_early, txlen);

            if ((result = SSL_write(ssl, txbuf, txlen)) <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            rxlen = SSL_read(ssl, rxbuf, rxcap);
            if (rxlen <= 0) {
                printf("Server closed connection\n");
                ERR_print_errors_fp(stderr);
                break;
            } else {
                rxbuf[rxlen] = 0;
                printf("Received: %s", rxbuf);
            }

            printf("Client exiting...\n");
        } else {

            printf("SSL connection to server failed\n\n");

            ERR_print_errors_fp(stderr);
        }

        if (ssl != NULL) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = NULL;
        }

        if (client_skt != -1) {
            close(client_skt);
            client_skt = -1;
        }
        count++;
    } while(count <= 1);
    // 1 回目:
    //   フル接続して session ticket を得る
    // 2 回目:
    //   session をセットし early data を送る
    //
    // という 0-RTT の学習シナリオを構成している。

    ssl = NULL;
    session = NULL;
    // 注意:
    // session_resumption() では SSL_SESSION_free(session) を呼んでいたが、
    // ここでは free せず NULL を代入しているだけである。
    // up_ref した session を保持しているなら、ここも解放しないとリークの可能性がある。
    //
    // レビュー観点では
    //   if (session != NULL) SSL_SESSION_free(session);
    // を追加したい箇所である。

    SSL_CTX_free(ssl_ctx);
}


int main(void)
{
    char s[2] = {0};
    // メニュー選択用の 1 文字入力バッファ。
    // 末尾 NUL を含めて 2 バイト確保している。

    printf("===== TLS1.3 test menu =====\n");
    printf("1: full handshake\n");
    printf("2: session resumption\n");
    printf("3: Hello Retry Request\n");
    printf("4: early data(0-RTT)\n");
    printf("\n");
    printf("CTRL+C to exit\n\n");
    printf("> ");

    scanf("%1s%*[^\n]%*c", s);
    // 1 文字だけ読み取る scanf。
    //
    // %1s
    //   最大 1 文字だけ文字列として読み取る
    //
    // %*[^\n]
    //   改行までの残り入力を読み捨てる
    //
    // %*c
    //   最後の改行文字を読み捨てる
    //
    // シンプルなメニュー入力としては妥当で、
    // 入力バッファに余計な文字が残りにくいよう工夫されている。

    switch(s[0]){
        case '1':
            full_handshake();
            // 通常の TLS 1.3 フルハンドシェイクを実行する。
            break;
        case '2':
            session_resumption();
            // session ticket を使った再開接続を試す。
            break;
        case '3':
            hello_retry_request();
            // グループ交渉を工夫して HRR を観察する。
            break;
        case '4':
            early_data();
            // session resumption を土台に 0-RTT を試す。
            break;
        default:
            // 想定外入力時は何もせず終了する。
            break;
    }
}
