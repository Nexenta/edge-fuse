# NexentaEdge Edge-X S3 POSIX compatible file system

High-Performance FUSE library to access Edge-X S3 API.

Tested and supported platforms:

- Linux x86 64-bit
- Mac OSX x86 64-bit
- Linux ARM 64-bit, mobile platforms (coming soon)
- Windows x86 64-bit (coming soon)

NexentaEdge Extended S3 API provides unique benefits which can be useful for Machine Deep Learning, Big Data and IoT frameworks:

* Mount S3 objects for fast File/POSIX access avoid unnecessary copy, fetch only needed datasets
* Optimized for local acces with fast Level-2 cache on SSD/NVMe
* Extended S3 feature set: Append, Range Writes, Object/Bucket snapshots, Key-Value Object access
* Data Reduction with global inline de-duplication, compression and erasure encoding
* Cost Reduction File/Block/DB access with S3 economics

## Use cases details

* Advanced Versioned S3 Object Append and RW "Object as File" access
* S3 Object as a Key-Value database, including integrations w/ Caffe, TensorFlow, Spark, Kafka, etc
* High-performance Versioned S3 Object Stream Session (RW), including FUSE library to mount an object
* Management API for Snapshots and Clones, including Bucket instantaneous snapshots
* Transparent NFS to/from S3 bucket access, “ingest via NFS, read via S3” or vice-versa

Comparision to existing cloud object storage APIs:

![fig1: EdgeVsS3](https://raw.githubusercontent.com/nexenta/nedge-dev/master/images/EdgeVsS3.png)

## Quick start

Give Edge-X S3 a try in easy to run single command installation:

```console
# location where to keep blobs
mkdir /var/tmp/data
    
# start nexenta/nedge daemon and Edge-X S3 compatible service
docker run --name s3data -v /etc/localtime:/etc/localtime:ro -v /var/tmp/data:/data -d \
    nexenta/nedge start -j ccowserv -j ccowgws3

```

Follow up with our Community! Please join us at the [NexentaEdge Devops community](https://community.nexenta.com/s/topic/0TOU0000000brtXOAQ/nexentaedge) site.

* [Register DevOps account and obtain license key here](https://community.nexenta.com/s/devops-edition)
* Use e-mailed ACTIVATION_KEY to activate installation

The following are the steps to initialize, setup region namespace, tenant, service:
    
```console
# setup alias for easy CLI style management
alias neadm="docker exec -it s3data neadm"
    
# verify that service is running
neadm system status
    
# initialize and setup devops license
neadm system init
neadm system license set online ACTIVATION_KEY
    
# setup simple Edge-X S3 service
neadm cluster create region1
neadm tenant create region1/tenant1
neadm bucket create region1/tenant1/bk1
neadm service create s3 s3svc
neadm service serve s3svc region1/tenant1
neadm service add s3svc SID  # use neadm system status to find out server id
neadm service restart s3svc
neadm service show s3svc
    
# assuming that default Docker bridge address asigned to container
# is 172.17.0.3 verify that Edge-X S3 port is listening
curl http://172.17.0.3:9982
```

Setup GUI for easy on-going management and monitoring:

```console
docker run -e API_ENDPOINT=http://172.17.0.3:8080 -p 3000:3000 \
    nexenta/nedgeui:2.1.0
```

* Point browser to the host's port 3000
* Default user/password: admin/nexenta
* You know show be able to manage and monitor your simple single node cluster!

![fig2: gui-s3svc](https://raw.githubusercontent.com/nexenta/nedge-dev/master/images/nedgeui-s3svc.png)

# Mount Edge-X S3 bucket for R/W access

While mounted, objects remain versioned, searchable and globally accessible (multi-site replication case).

## Compile edgefs binary

```console
make all
```

## Build Debian package

```console
make deb
```

## Build RPM package

```console
make rpm
```

## Install package or binary and mount bucket

```console
mkdir /mnt/bk1
edgefs -c - -f http://172.17.0.3:9982/bk1 /mnt/bk1
```

At this point EdgeFS module emulates POSIX access to S3 bucket and would use Extended Edge API to enable high performance R/W access at /mnt/bk1 mount point. At the moment, we only emulate flat bucket operations.

## Regression tests

Build fstest utility and execute TAP tests from the mount point, example:

```console
cd /mnt/bk1
prove -r /path/to/edge-fuse/tests
```

Learn more about [Edge-X S3 API here](https://edgex.docs.apiary.io).

Ask immediate question on [NexentaEdge Developers Channel](https://nexentaedge.slack.com/messages/general/)

**Note:** The full documentation for NexentaEdge Enterprise Edition is [available here](https://nexenta.com/products/nexentaedge).
