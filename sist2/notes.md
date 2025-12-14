https://github.com/sist2app/sist2/releases/download/3.3.6/sist2-x64-linux

sist2 scan ~/Documents

sist2 scan \
    --threads 4 --content-size 16000000 --thumbnail_count-quality 2 --archive shallow \
    --name "My Documents" --rewrite-url "http://nas.domain.local/My Documents/" \
    ~/Documents -o ./documents.sist2




sist2 scan /home/user -o ./fs.sist2 --incremental
sist2 sqlite-index ./fs.sist2 --search-index search.sist2
sist2 web --auth admin:gofish --bind 0.0.0.0:8888 --search-index search.sist2 fs.sist2





Build:

docker build . -t my-sist2-image
# Copy sist2 executable from docker image
docker run --rm --entrypoint cat my-sist2-image /root/sist2 > sist2-x64-linux
