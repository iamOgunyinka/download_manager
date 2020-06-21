#include <boost/asio.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <fstream>
#include <iostream>
#include <optional>
#include <string_view>
#include <vector>

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = net::ssl;

namespace no_name {
namespace utilities {
struct uri {
  uri(std::string_view url_s);
  std::string const &path() const;
  std::string const &host() const;
  std::string const &protocol() const;

private:
  void parse(std::string_view);
  std::string host_;
  std::string path_;
  std::string protocol_;
  std::string query_;
};

uri::uri(std::string_view url_s) { parse(url_s); }

std::string const &uri::protocol() const { return protocol_; }

std::string const &uri::path() const { return path_; }

std::string const &uri::host() const { return host_; }

void uri::parse(std::string_view url_s) {
  std::string const prot_end{"://"};
  auto prot_i =
      std::search(url_s.begin(), url_s.end(), prot_end.begin(), prot_end.end());
  protocol_.reserve(
      static_cast<std::size_t>(std::distance(url_s.cbegin(), prot_i)));
  std::transform(url_s.begin(), prot_i, std::back_inserter(protocol_),
                 [](int c) { return std::tolower(c); });
  if (prot_i == url_s.end()) {
    prot_i = url_s.begin();
  } else {
    std::advance(prot_i, prot_end.length());
  }
  auto const path_i = std::find(prot_i, url_s.end(), '/');
  host_.reserve(static_cast<std::size_t>(std::distance(prot_i, path_i)));
  std::transform(prot_i, path_i, std::back_inserter(host_),
                 [](int c) { return std::tolower(c); });
  auto query_i = std::find(path_i, url_s.end(), '?');
  path_.assign(path_i, query_i);
  if (query_i != url_s.end())
    ++query_i;
  query_.assign(query_i, url_s.end());
}

} // namespace utilities
class download_manager {
  template <typename T>
  using optional_parser = std::optional<http::request_parser<T>>;

  net::ip::tcp::resolver resolver_;
  utilities::uri const url_;
  http::request<http::empty_body> request_{};
  std::optional<net::ip::basic_resolver_results<net::ip::tcp>> query_result_{};
  std::optional<beast::ssl_stream<beast::tcp_stream>> ssl_stream_;
  std::optional<beast::flat_buffer> header_buffer_{};
  std::optional<http::request_parser<http::empty_body>> empty_body_parser_{};

  std::vector<char> body_buffer_{};
  std::ofstream out_file_{};
  std::string const output_path_;

private:
  void perform_connection();
  void on_connection_established(beast::error_code);
  void on_ssl_handshake(beast::error_code);
  void perform_ssl_handshake();
  void send_https_data();
  void on_data_sent(beast::error_code, std::size_t);
  void receive_data();
  void on_header_read(beast::error_code);
  void file_body_read(beast::error_code, std::size_t);

public:
  download_manager(net::io_context &io, ssl::context &ssl_context,
                   std::string_view url, std::string out_path)
      : resolver_{io}, url_{url}, ssl_stream_{std::in_place,
                                              net::make_strand(io),
                                              ssl_context},
        output_path_{out_path} {}
  void download_file() {
    if (!SSL_set_tlsext_host_name(ssl_stream_->native_handle(),
                                  url_.host().c_str())) {
      beast::error_code ec{static_cast<int>(::ERR_get_error()),
                           net::error::get_ssl_category()};
      std::cerr << ec.message() << std::endl;
      return;
    }
    resolver_.async_resolve(
        url_.host(), "https", [=](boost::system::error_code ec, auto results) {
          if (!ec) {
            query_result_.emplace(std::move(results));
            return perform_connection();
          }
          std::cerr << "unable to resolve \"" << url_.host() << "\", because("
                    << ec.message() << ")" << std::endl;
        });
  }
};

void download_manager::perform_connection() {
  beast::get_lowest_layer(*ssl_stream_).expires_after(std::chrono::seconds(15));
  beast::get_lowest_layer(*ssl_stream_)
      .async_connect(*query_result_, [=](beast::error_code ec, auto const) {
        on_connection_established(ec);
      });
}

void download_manager::on_connection_established(beast::error_code ec) {
  if (!ec) {
    return perform_ssl_handshake();
  }
  std::cerr << "connection failed because(" << ec.message() << ")" << std::endl;
}

void download_manager::perform_ssl_handshake() {
  beast::get_lowest_layer(*ssl_stream_).expires_after(std::chrono::seconds(15));
  ssl_stream_->async_handshake(
      net::ssl::stream_base::client,
      [=](beast::error_code ec) { return on_ssl_handshake(ec); });
}

void download_manager::on_ssl_handshake(beast::error_code ec) {
  if (!ec || (ec.category() == net::error::get_ssl_category() &&
              ec.value() == ERR_PACK(ERR_LIB_SSL, 0, SSL_R_SHORT_READ))) {
    std::cout << "on ssl_handshake: " << ec.message() << std::endl;
    return send_https_data();
  }
  std::cerr << "SSL Handshake failed because(" << ec.message() << ")"
            << std::endl;
}

void download_manager::send_https_data() {
  request_.clear();
  request_.method(http::verb::get);
  request_.version(11);
  request_.target(url_.path());
  request_.set(http::field::host, url_.host());
  request_.set(http::field::user_agent,
               "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)");
  request_.keep_alive(true);
  request_.body() = {};

  std::cout << request_ << std::endl;

  beast::get_lowest_layer(*ssl_stream_).expires_after(std::chrono::seconds(10));
  http::async_write(
      *ssl_stream_, request_,
      beast::bind_front_handler(&download_manager::on_data_sent, this));
}

void download_manager::on_data_sent(beast::error_code ec,
                                    std::size_t const sz) {
  if (!ec) {
    return receive_data();
  }
  std::cout << sz << " " << ec.message() << std::endl;
}

void download_manager::receive_data() {
  header_buffer_.emplace();
  empty_body_parser_.emplace();
  beast::get_lowest_layer(*ssl_stream_).expires_after(std::chrono::seconds(10));

  http::async_read_header(
      *ssl_stream_, *header_buffer_, *empty_body_parser_,
      [this](beast::error_code ec, std::size_t const) { on_header_read(ec); });
}

void download_manager::on_header_read(beast::error_code ec) {
  if (ec) {
    std::cerr << "An error occurred: " << ec.message() << std::endl;
    return;
  }
  constexpr std::size_t max_usable_memory = 102'400; // 100MB
  auto const body_length_str =
      empty_body_parser_->get()[http::field::content_length].to_string();
  std::size_t body_length = 1024 * 20; // read 20MB at once into memory
  try {
    body_length = std::stoul(body_length_str); // or read all
  } catch (std::exception const &) {
  }
  out_file_.open(output_path_);
  if (!out_file_) {
    std::cerr << "Unable to open file for write" << std::endl;
    return;
  }
  if (body_length > max_usable_memory) {
    body_buffer_.resize(max_usable_memory, '\0');
  } else {
    body_buffer_.resize(body_length, '\0');
  }
  return ssl_stream_->async_read_some(
      net::mutable_buffer(body_buffer_.data(), body_buffer_.size()),
      [this](beast::error_code ec, std::size_t const sz) {
        file_body_read(ec, sz);
      });
}

void download_manager::file_body_read(beast::error_code ec,
                                      std::size_t const bytes_read) {
  if (ec == http::error::end_of_stream) {
    if (out_file_.is_open())
      out_file_.close();
    return;
  } else if (ec) {
    std::cerr << ec.message() << std::endl;
    return;
  }
  assert((bytes_read <= body_buffer_.size()) && bytes_read > 0);
  auto const result = std::string_view(body_buffer_.data(), bytes_read);
  out_file_ << result;
  ssl_stream_->async_read_some(
      net::mutable_buffer(body_buffer_.data(), body_buffer_.size()),
      [this](beast::error_code ec, std::size_t const sz) {
        file_body_read(ec, sz);
      });
}
} // namespace no_name

void run_download_manager(net::io_context &io, ssl::context &ssl_context,
                          std::vector<std::string> const &arguments) {
  std::string_view url = arguments[0];
  std::string const dest_path = arguments.size() > 1 ? arguments[1] : "./a.out";
  no_name::download_manager manager{io, ssl_context, url, dest_path};
  manager.download_file();
  io.run();
}

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <URL> [<output_file=./a.out>]"
              << std::endl;
    return -1;
  }
  std::vector<std::string> const arguments(argv + 1, argv + argc);
  net::io_context io_context{};
  ssl::context ssl_context(ssl::context::tlsv11_client);
  ssl_context.set_default_verify_paths();
  ssl_context.set_verify_mode(ssl::verify_none);

  run_download_manager(io_context, ssl_context, arguments);
  return 0;
}
