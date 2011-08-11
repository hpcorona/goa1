goa1
======

OAuth v1.0 server helper.

Utilities to parse a http.Request and validate if the request is valid.

To parse a request:
<code>
goa1.ParseRequest(*http.Request) (*OAuthRequest, os.Error)
</code>

To validate a request:
<code>
goa1.Validate(*OAuthRequest, clientsecret string, tokensecret string) (bool, os.Error)
</code>

This package is not intended to be an "all-in-one" solution for an oauth v1.0 server.
Instead it will only help you validating a request.

The management of nonce, timestamp, access tokens, validation tokens, customer secrets,
and all that other stuff is not included here.



## License

(The MIT License)

Copyright (c) 2011 Hilario Pérez Corona &lt;hpcorona@gmail.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
