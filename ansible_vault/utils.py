__all__ = ['to_bytes', 'to_text']


def to_bytes(obj, encoding='utf-8', errors='strict'):
  """Makes sure that a string is a byte string.

  Args:
    obj: An object to make sure is a byte string.
    encoding: The encoding to use to transform from a text string to
        a byte string. Defaults to using 'utf-8'.
    errors: The error handler to use if the text string is not
        encodable using the specified encoding. Any valid codecs error
        handler may be specified.
  Returns: Typically this returns a byte string.
  """
  if isinstance(obj, bytes):
    return obj
  return bytes(obj, encoding=encoding, errors=errors)


def to_text(obj, encoding='utf-8', errors='strict'):
  """Makes sure that a string is a text string.

  Args:
    obj: An object to make sure is a text string.
    encoding: The encoding to use to transform from a byte string to
        a text string. Defaults to using 'utf-8'.
    errors: The error handler to use if the byte string is not
        decodable using the specified encoding. Any valid codecs error
        handler may be specified.
  Returns: Typically this returns a text string.
  """
  if isinstance(obj, str):
    return obj
  return str(obj, encoding=encoding, errors=errors)
