#include "common.h"  // 共通ヘッダ。
                     // おそらくここには以下のような内容がまとめられている。
                     // - 標準ライブラリの include
                     // - OpenSSL 関連ヘッダ
                     // - create_socket / create_context のプロトタイプ宣言
                     // - 必要な定数や共通設定
                     //
                     // このように共通化しておくことで、サーバ側とクライアント側で
                     // 同じ宣言を再利用でき、宣言の重複や不整合を防げる。


/* ポート番号 */
const int server_port = 443;  // サーバが待ち受ける TCP ポート番号。
                              //
                              // 443 は HTTPS の標準ポートであり、
                              // TLS 通信を行うサーバとしては自然な設定である。
                              //
                              // ただし、UNIX/Linux では 1024 未満のポートは
                              // 特権ポート (privileged port) であるため、
                              // 一般ユーザーで bind() するには権限不足になることがある。
                              //
                              // 学習環境や Docker コンテナでは root 権限で動かしているため
                              // そのまま使える場合があるが、通常のユーザー権限で動かすなら
                              // 10443 のような 1024 以上のポートにする方が扱いやすい。


/* ソケット作成関数 */
int create_socket(bool isServer, int family, int socktype)
{
    int skt;                  // socket() が返すソケットファイルディスクリプタを格納する変数。
    int optval = 1;           // setsockopt() で SO_REUSEADDR を有効にするときに使う値。
                              // 1 を渡すことで「オプション有効」を意味する。
    struct sockaddr_in addr;  // IPv4 用ソケットアドレス構造体。
                              //
                              // sockaddr_in は IPv4 専用であり、
                              // 主に以下の情報を保持する。
                              // - アドレスファミリ (AF_INET)
                              // - ポート番号
                              // - IP アドレス
                              //
                              // 今回は family 引数があるが、実際の実装では sockaddr_in を
                              // 使っているため、実質的には IPv4 を前提にしている。
                              // もし IPv6 も扱いたいなら sockaddr_in6 や sockaddr_storage、
                              // あるいは getaddrinfo() ベースの実装が必要になる。

    /* ソケットの作成 */
    skt = socket(family, socktype, 0);
    // socket() は通信に使う「通信端点」を OS に作らせるシステムコールである。
    //
    // 引数の意味:
    //   family
    //     アドレスファミリを指定する。
    //     例:
    //       AF_INET  -> IPv4
    //       AF_INET6 -> IPv6
    //
    //   socktype
    //     ソケット種別を指定する。
    //     例:
    //       SOCK_STREAM -> TCP
    //       SOCK_DGRAM  -> UDP
    //
    //   0
    //     通常はプロトコル番号を OS に自動選択させる。
    //     AF_INET + SOCK_STREAM なら TCP が選ばれる。
    //
    // 戻り値:
    //   成功時 -> 0 以上のファイルディスクリプタ
    //   失敗時 -> -1
    //
    // TLS は直接ネットワーク上で動くのではなく、
    // 通常は TCP ソケットの上に載って動く。
    // したがって、まずはこの socket() によって通常の TCP 通信路を用意し、
    // その上に OpenSSL の SSL オブジェクトを重ねる、という順序になる。

    if (skt < 0) {
        perror("Unable to create socket");
        // perror() は直前の失敗原因を errno から読み取り、
        // 指定文字列とともに標準エラー出力へ表示する。
        //
        // 例:
        //   Unable to create socket: Address family not supported by protocol
        //
        // ソケット作成に失敗した時点で以後の処理は成立しないため、
        // ここでは即座に終了している。
        exit(EXIT_FAILURE);
    }

    /* サーバソケットの場合 */
    if (isServer) {
        // isServer == true のときは、このソケットを「待受用ソケット」として初期化する。
        //
        // サーバソケットの初期化手順は典型的に次の通りである。
        //
        //   1. socket() でソケット生成
        //   2. bind()   で IP アドレスとポートを紐付け
        //   3. listen() で待受状態に移行
        //
        // クライアント側では通常 bind/listen は不要であり、
        // socket() 後に connect() を使って接続先へ接続する。
        addr.sin_family = family;
        // ソケットアドレスにアドレスファミリを設定する。
        //
        // ここでは family をそのまま使っているが、
        // 構造体が sockaddr_in である以上、実際には AF_INET を前提にしている。
        // もし family に AF_INET6 が渡ると整合しないため、
        // 実運用ではここを明示的に AF_INET に固定するか、
        // family に応じて構造体そのものを切り替える方が安全である。

        addr.sin_port = htons(server_port);
        // ポート番号をネットワークバイトオーダへ変換して設定する。
        //
        // htons = host to network short
        //
        // ネットワークプロトコルではビッグエンディアンが使われるため、
        // CPU のネイティブなバイト順と異なる環境でも正しく通信できるよう、
        // 明示的に変換する必要がある。
        //
        // server_port は 443 なので、
        // ここでは「HTTPS/TLS 用の待受ポート 443」に bind することになる。

        addr.sin_addr.s_addr = INADDR_ANY;
        // サーバが受信待ちする IP アドレスを設定する。
        //
        // INADDR_ANY は「すべてのローカルインターフェースで受け付ける」
        // という意味である。
        //
        // たとえばホストが複数の IP アドレスを持っていても、
        // それらすべてに対する接続要求をこのソケットで受けられる。
        //
        // 学習用途や単純なサーバでは便利だが、
        // 実運用では特定の IP アドレスだけで待受したいこともある。

        /* アドレスの再利用 再起動用 */
        if (setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
                < 0) {
            // setsockopt() はソケットに対してオプションを設定するシステムコール。
            //
            // ここでは SO_REUSEADDR を有効にしている。
            //
            // SOL_SOCKET
            //   ソケット層のオプションであることを表す。
            //
            // SO_REUSEADDR
            //   直前に使っていたアドレス/ポートを再利用しやすくする。
            //
            // これは特にサーバ再起動時に重要である。
            // TCP ソケットは終了後もしばらく TIME_WAIT 状態に残るため、
            // 何もしないと
            //
            //   bind: Address already in use
            //
            // になって再起動直後に同じポートへ bind できないことがある。
            //
            // SO_REUSEADDR を付けることで、その問題を緩和できる。
            //
            // TLS サーバの学習や実験ではサーバを何度も再起動するため、
            // この設定はほぼ必須と言ってよい。
            perror("setsockopt(SO_REUSEADDR) failed");
            exit(EXIT_FAILURE);
        }

        /* ソケットの登録 */
        if (bind(skt, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
            // bind() はソケットに対して「どの IP アドレス・ポートで待受するか」
            // を登録するシステムコールである。
            //
            // 引数:
            //   skt
            //     対象ソケット
            //
            //   (struct sockaddr*) &addr
            //     sockaddr_in を汎用 sockaddr* にキャストして渡している。
            //     ソケット API は IPv4/IPv6 などを共通化するために
            //     struct sockaddr* を受け取る設計になっている。
            //
            //   sizeof(addr)
            //     アドレス構造体のサイズ
            //
            // bind に成功すると、
            // 「このソケットはこのアドレスとポートを担当する」
            // という状態になる。
            //
            // まだこの段階では接続待ち状態ではない。
            // その次に listen() を呼ぶ必要がある。
            perror("Unable to bind");
            exit(EXIT_FAILURE);
        }

        /* ソケットの接続準備 */
        if (listen(skt, 1) < 0) {
            // listen() はソケットを「接続待受状態」に移行させる。
            //
            // 第2引数 1 はバックログであり、
            // 未受理の接続要求を最大いくつ待たせるかの目安である。
            //
            // ここでは 1 にしているため、かなり小さい。
            // 学習用の単純な 1 接続サーバとしては十分だが、
            // 実運用サーバではより大きな値が使われる。
            //
            // listen により TCP の待受ソケットが完成し、
            // この後 accept() を使ってクライアント接続を受理できる。
            //
            // TLS の流れでは、
            //   listen() / accept()
            // の後に、その accepted socket に対して
            //   SSL_new()
            //   SSL_set_fd()
            //   SSL_accept()
            // を行うのが典型的なサーバ実装になる。
            perror("Unable to listen");
            exit(EXIT_FAILURE);
        }
    }

    return skt;
    // 作成したソケットファイルディスクリプタを返す。
    //
    // サーバ側なら:
    //   bind + listen 済みの「待受ソケット」
    //
    // クライアント側なら:
    //   まだ接続先に connect していない「生のソケット」
    //
    // という意味になる可能性が高い。
    //
    // つまりこの関数は、
    // 「ソケットを生成し、必要なら待受状態まで進める」
    // という共通処理をカプセル化している。
}

/* SSLコンテキスト作成関数 */
SSL_CTX* create_context(bool isServer)
{
    const SSL_METHOD *method;  // TLS の動作方針を表すメソッドオブジェクトへのポインタ。
                               // サーバ用かクライアント用かで異なるメソッドを選ぶ。
    SSL_CTX *ctx;              // SSL/TLS 設定全体を保持するコンテキスト。
                               //
                               // SSL_CTX は OpenSSL における「接続共通設定の入れ物」であり、
                               // 1 接続ごとの SSL オブジェクト SSL とは別物である。
                               //
                               // ここに証明書・秘密鍵・検証ポリシー・暗号スイートなどを設定し、
                               // 実際の接続時には SSL_new(ctx) で個別セッションを作る。

    if (isServer)
        /* サーバ */
        method = TLS_server_method();
        // サーバ用の汎用 TLS メソッドを選択する。
        //
        // TLS_server_method() は
        // 「サーバとして TLS を話すための実装方針」
        // を表す OpenSSL の API である。
        //
        // 昔は TLSv1_2_server_method() のようにバージョンごとの API もあったが、
        // 現在は TLS_server_method() / TLS_client_method() を使い、
        // 必要なら別途 min/max version を制限する形が一般的である。
    else
        /* クライアント */
        method = TLS_client_method();
        // クライアント用の汎用 TLS メソッドを選択する。
        //
        // こちらは「クライアントとして TLS を開始する側」の設定である。
        // サーバとクライアントではハンドシェイク開始方向や証明書検証の役割が異なるため、
        // メソッドも分けている。
        //
        // この設計により、同じ create_context() という関数で
        // サーバ用・クライアント用双方のコンテキストを作れる。

    ctx = SSL_CTX_new(method);
    // SSL_CTX_new() は、指定したメソッドに基づいて SSL_CTX を生成する。
    //
    // ここで作られるのはまだ「TLS 接続そのもの」ではなく、
    // TLS 通信に必要な設定の土台である。
    //
    // 典型的には、この後に以下のような設定を追加する。
    //
    // サーバ側:
    //   SSL_CTX_use_certificate_file()
    //   SSL_CTX_use_PrivateKey_file()
    //
    // クライアント側:
    //   SSL_CTX_load_verify_locations()
    //   SSL_CTX_set_verify()
    //
    // 共通:
    //   SSL_CTX_set_min_proto_version()
    //   SSL_CTX_set_cipher_list()
    //
    // つまりこの関数は、
    // 「TLS 通信の前提設定を入れる箱を作る」
    // 役割を担っている。

    if (ctx == NULL) {
        perror("Unable to create SSL context");
        // ここでの perror() は errno ベースのエラーを表示するが、
        // OpenSSL の詳細エラーは必ずしも errno に入らない。
        // そのため次の ERR_print_errors_fp(stderr) が重要である。
        ERR_print_errors_fp(stderr);
        // OpenSSL のエラーキューに溜まった詳細エラーを stderr へ出力する。
        //
        // これにより、たとえば
        // - 利用可能なメソッドがない
        // - OpenSSL の初期化が不十分
        // - 内部ライブラリエラー
        // などを確認できる。
        //
        // OpenSSL を使うコードでは、
        // perror() だけでなく ERR_print_errors_fp() を併用するのが基本である。
        exit(EXIT_FAILURE);
    }

    return ctx;
    // 正常に作成された SSL_CTX を返す。
    //
    // この ctx は「接続共通の TLS 設定」を表すため、
    // 実際の通信ではこの後たとえば次のように使う。
    //
    //   SSL *ssl = SSL_new(ctx);
    //   SSL_set_fd(ssl, skt);
    //
    // サーバ側:
    //   SSL_accept(ssl);
    //
    // クライアント側:
    //   SSL_connect(ssl);
    //
    // つまり、通信全体の流れは概念的に次のようになる。
    //
    //   create_context()
    //       ↓
    //   create_socket()
    //       ↓
    //   SSL_new()
    //       ↓
    //   SSL_set_fd()
    //       ↓
    //   SSL_accept() or SSL_connect()
    //       ↓
    //   SSL_read() / SSL_write()
    //
    // このように見ると、
    // create_context() は TLS 通信の「準備段階」を担う重要な関数である。
}
