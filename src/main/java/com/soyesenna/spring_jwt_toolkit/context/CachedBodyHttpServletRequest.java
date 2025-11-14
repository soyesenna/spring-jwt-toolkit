package com.soyesenna.spring_jwt_toolkit.context;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import org.springframework.util.StreamUtils;

/**
 * {@link HttpServletRequestWrapper} that caches the request body so it can be read multiple times.
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

  private final byte[] cachedBody;

  public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
    super(request);
    this.cachedBody = StreamUtils.copyToByteArray(request.getInputStream());
  }

  @Override
  public ServletInputStream getInputStream() {
    final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(this.cachedBody);
    return new ServletInputStream() {
      @Override
      public int read() {
        return byteArrayInputStream.read();
      }

      @Override
      public boolean isFinished() {
        return byteArrayInputStream.available() == 0;
      }

      @Override
      public boolean isReady() {
        return true;
      }

      @Override
      public void setReadListener(ReadListener readListener) {
        // no-op
      }
    };
  }

  @Override
  public BufferedReader getReader() {
    Charset charset =
        getCharacterEncoding() != null
            ? Charset.forName(getCharacterEncoding())
            : StandardCharsets.UTF_8;
    return new BufferedReader(
        new InputStreamReader(this.getInputStream(), charset));
  }

  public byte[] getCachedBody() {
    return this.cachedBody;
  }
}
