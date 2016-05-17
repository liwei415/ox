method 1: curl -H "Content-Type:jpeg" --data-binary @bb.jpg "http://127.0.0.1:9527/post"
method 2: curl -F "blob=@bb.jpg;type=image/jpeg" "http://127.0.0.1:9527/post"
