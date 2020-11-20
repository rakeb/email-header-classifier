UNCC Email Header Classifier is uploaded.

Can be accessed through the following url:
  http://18.221.78.232/panacea-uncc/upload-email-header-for-testing/
  
[Please note that the IP "18.221.78.232" in the above link may get changed or the server may be down, email me if any of the case occur: mislam7@uncc.edu]

We are providing two API for Training Data and Testing Data:

Training Email Header API:

POST = http://18.221.78.232/panacea-uncc/upload-email-header-for-training/

Sample application/json: 

```
{
  "req-id": request ID,
  "number-of-header": n,
  "header-list": [{header 1 as json object}, {header 2 as json object}, ... , {header n as json object}]
}
```

Complete working sample example for TRAINING:
```
input:
{
        "req-id": 1,
        "number-of-header": 4,
        "header-list": [
            {
                "Return-Path": "<postnett16@gmail.com>",
                "Received": "by 10.2.159.148 with HTTP; Sun, 31 Dec 2017 11:11:23 -0800 (PST)",
                "DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=gmail.com; s=20161025;\n        h=mime-version:reply-to:from:date:message-id:subject:to;\n        bh=+tb5NQTdmm4XItRSb7nKgyzr1IRMR3P15HfouJbfHW4=;\n        b=oJ1WXlEKNgMapjLSY5ja862I1WrxxNAgJd7E3ejDiRBV9YqyK25yy4aqHpxxpZ9TVM\n         Ig1WCQ4kSWdPjv5VweLYjZUmes2m4fthvTCNZe5ywOoBOsTrnds83yj+51Qf4hyv6MK7\n         R2c9Gwt/n/+flUkLLIWm15/KoTmOF264ISXPVoX37rpRoG83DQA6xqPyeBka4nzuhwr1\n         SsJw+Uo8koU1Uc/j8THmZ5lobqWQ8h3c+ZaLbfEA0fSgm/EolrozhyRWOekAXwQqJ1sv\n         s+gWfbSIOfE2u/4nubCgL4XPKrxEcG0p6plzptr2/ditmp2LFTruKWBKzu5UUumG1lLW\n         zeFA==",
                "X-Google-DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=1e100.net; s=20161025;\n        h=x-gm-message-state:mime-version:reply-to:from:date:message-id\n         :subject:to;\n        bh=+tb5NQTdmm4XItRSb7nKgyzr1IRMR3P15HfouJbfHW4=;\n        b=jm6D/c4CzrYOOtQ1zns8kH9WzXJ3JlzIaDSA2NKbhdasozJ0IwMwytaCtXMw7+d8mG\n         O1BRqlqWsQgxcAsCdAZtO8AUzkE8K50y+Gs+8zDFCqMbx3fJz4KqRPSBXLAP5K1mnbRS\n         dJ7VTQOE9EOTLEExjKqwwlc6+52asH8GrFuzTf/wxnjPPyoKFqvLYzRjLhxLe7liMOf1\n         +XhRze8opTI2gtpEM8L5+ZSXhc+kPo7SMsr9pJyUscj0FyolQqEiQK598lpJeUHdR/tI\n         Y31BYEwo1hrhZ1XvNnB55NU5FcsRjr6tmEhk/GawpSwt+Gt1vrww+rjCtDwLFd2xza7k\n         0Uuw==",
                "X-Gm-Message-State": "AKGB3mKmk3yoWJauyXMgmV/G42IFY9zv2t4IkoH2xv9Cylu+5ZeX8Arj\n\t6sUzcAkKH8vaqb7ElDE2sROKHGyweuEpIzUJzmk=",
                "X-Google-Smtp-Source": "ACJfBovGDHF5ZZuhUIu6Cwk5Qj/ThiycrRLKknBd4qUIUNK/gqohP4qSwlLPZMBwqcQY1aRwQVh+whoUjr4bRngWBs8=",
                "X-Received": "by 10.107.81.6 with SMTP id f6mr28377175iob.20.1514747484044; Sun,\n 31 Dec 2017 11:11:24 -0800 (PST)",
                "MIME-Version": "1.0", "Reply-To": "aa1@mail.com",
                "From": "<aa1@gmail.com>",
                "Date": "Sun, 31 Dec 2017 21:11:23 +0200",
                "Subject": "FIND MY ATTACHED LETTER FROM MRS MARIA SIBANDA & REPLY TO ME +27781779673",
                "To": "<uuu@gmail.com>",
                "Content-Type": "multipart/mixed; boundary=089e0825a7a0b63ed80561a7a103",
                "x-aol-global-disposition": "S", "X-AOL-VSS-INFO": "5800.7501/124996",
                "X-AOL-VSS-CODE": "clean",
                "X-AOL-SCOLL-AUTHENTICATION": "mtaiw-aaj08.mx.aol.com ; domain : gmail.com DKIM : pass",
                "X-AOL-SCOLL-DMARC": "mtaiw-aaj08.mx.aol.com ; domain : gmail.com ; policy : none ; result : P",
                "Authentication-Results": "mx.aol.com;\n\tspf=pass (aol.com: the domain gmail.com reports 209.85.223.195 as a permitted sender.) smtp.mailfrom=gmail.com;\n\tdkim=pass (aol.com: email passed verification from the domain gmail.com.) header.i=@gmail.com;\n\tdmarc=pass (aol.com: the domain gmail.com reports that Both SPF and DKIM strictly align.) header.from=gmail.com;",
                "X-AOL-REROUTE": "YES", "x-aol-sid": "3039ac1b03c55a49365c5078", "X-AOL-IP": "209.85.223.195",
                "X-AOL-SPF": "domain : gmail.com SPF : pass",
                "Message-ID": "dshjdhs@sasa.com",
                "References": "b@ccc.com",
                "User-Agent": "bdadsa",
                "X-Mailer": "aassa"},
            {"Return-Path": "<return@academia.edu>",
             "Received": "from hastavidafi.com (hastavidafi.com. [173.82.177.231])\n        by mx.google.com with ESMTP id k33si32168844pld.22.2017.12.31.15.52.29\n        for <trblake@gmail.com>;\n        Sun, 31 Dec 2017 15:52:29 -0800 (PST)",
             "Received-SPF": "softfail (google.com: domain of transitioning return@academia.edu does not designate 173.82.177.231 as permitted sender) client-ip=173.82.177.231;",
             "Authentication-Results": "mx.google.com;\n       dkim=pass header.i=@hastavidafi.com header.s=default header.b=22xBc5jN;\n       spf=softfail (google.com: domain of transitioning return@academia.edu does not designate 173.82.177.231 as permitted sender) smtp.mailfrom=return@academia.edu",
             "DKIM-Signature": "v=1; a=rsa-sha1; c=relaxed/relaxed; s=default; d=hastavidafi.com;\n h=List-Unsubscribe:From:Date:Subject:To:Message-Id:Content-Type:Content-Transfer-Encoding; i=1Qn2114re701J6c8ijH@7IT87H1R3yks7HY3061.hastavidafi.com;\n bh=nTxOTzstHioOKjaatigYIaQodNs=;\n b=22xBc5jNpA52c1cZ2c9FYd9gjjo4KIg8i1XShfEHsBuUUg6+ys3nldv19Q1VuFTeAVxxRaWkPpRa\n   M1DtHYsjWZIdwdMmV3DudBIEG/k97jKBvDG53kp30ZTzT/pp0lcWIxQ2PB+CGHiooA7eQb3h4+5z\n   8VEIix4RH08mPAl1+dI=",
             "DomainKey-Signature": "a=rsa-sha1; c=nofws; q=dns; s=default; d=hastavidafi.com;\n b=T2/LxPeJ3fFntl3lDjZY9ojpKD3KGOoHxR0EPtNMixzgA2sjZuT8G8dvk/m4In5wWe+z+jEZ/qhr\n   I926Pf1wDEWCCf2puBAh3xYvatXyKoCtFAqipLaJBjtLu6uqb3JC2czgY/owUJC0ZGo8fq7gXLGT\n   R3n9OrpRVrjpBeKhoxU=;",
             "List-Unsubscribe": "<4NQC20m453CYJo32P48-64Tg1N209T8211IFaZJ@hastavidafi.com>",
             "From": "<aa2@7IT87H1R3yks7HY3061.hastavidafi.com>",
             "Date": "Sun, 31 Dec 2017 15:53:18 -0800 (PDT)",
             "Subject": "=?UTF-8?B?TGV0IGJlIE5hdWdodHkgdGhpcyBDaHJpc3RtYXM=?=",
             "To": "<uuu@gmail.com>",
             "Message-Id": "<7joz19dyIWVY9562294-7Wt4X6QMfVDe0274223@hastavidafi.com>",
             "X-EMMAIL": "trblake@hastavidafi.com", "Content-Type": "text/html; charset=utf-8",
             "Content-Transfer-Encoding": "base64",
             "Message-ID": "dshjdhs@bbb.com",
             "References": "a@ddd.com",
             "X-Mailer": "ffsa"},
            {"Return-Path": "<postnett16@gmail.com>",
             "Received": "by 10.2.159.148 with HTTP; Sun, 31 Dec 2017 11:11:23 -0800 (PST)",
             "DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=gmail.com; s=20161025;\n        h=mime-version:reply-to:from:date:message-id:subject:to;\n        bh=+tb5NQTdmm4XItRSb7nKgyzr1IRMR3P15HfouJbfHW4=;\n        b=oJ1WXlEKNgMapjLSY5ja862I1WrxxNAgJd7E3ejDiRBV9YqyK25yy4aqHpxxpZ9TVM\n         Ig1WCQ4kSWdPjv5VweLYjZUmes2m4fthvTCNZe5ywOoBOsTrnds83yj+51Qf4hyv6MK7\n         R2c9Gwt/n/+flUkLLIWm15/KoTmOF264ISXPVoX37rpRoG83DQA6xqPyeBka4nzuhwr1\n         SsJw+Uo8koU1Uc/j8THmZ5lobqWQ8h3c+ZaLbfEA0fSgm/EolrozhyRWOekAXwQqJ1sv\n         s+gWfbSIOfE2u/4nubCgL4XPKrxEcG0p6plzptr2/ditmp2LFTruKWBKzu5UUumG1lLW\n         zeFA==",
             "X-Google-DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=1e100.net; s=20161025;\n        h=x-gm-message-state:mime-version:reply-to:from:date:message-id\n         :subject:to;\n        bh=+tb5NQTdmm4XItRSb7nKgyzr1IRMR3P15HfouJbfHW4=;\n        b=jm6D/c4CzrYOOtQ1zns8kH9WzXJ3JlzIaDSA2NKbhdasozJ0IwMwytaCtXMw7+d8mG\n         O1BRqlqWsQgxcAsCdAZtO8AUzkE8K50y+Gs+8zDFCqMbx3fJz4KqRPSBXLAP5K1mnbRS\n         dJ7VTQOE9EOTLEExjKqwwlc6+52asH8GrFuzTf/wxnjPPyoKFqvLYzRjLhxLe7liMOf1\n         +XhRze8opTI2gtpEM8L5+ZSXhc+kPo7SMsr9pJyUscj0FyolQqEiQK598lpJeUHdR/tI\n         Y31BYEwo1hrhZ1XvNnB55NU5FcsRjr6tmEhk/GawpSwt+Gt1vrww+rjCtDwLFd2xza7k\n         0Uuw==",
             "X-Gm-Message-State": "AKGB3mKmk3yoWJauyXMgmV/G42IFY9zv2t4IkoH2xv9Cylu+5ZeX8Arj\n\t6sUzcAkKH8vaqb7ElDE2sROKHGyweuEpIzUJzmk=",
             "X-Google-Smtp-Source": "ACJfBovGDHF5ZZuhUIu6Cwk5Qj/ThiycrRLKknBd4qUIUNK/gqohP4qSwlLPZMBwqcQY1aRwQVh+whoUjr4bRngWBs8=",
             "X-Received": "by 10.107.81.6 with SMTP id f6mr28377175iob.20.1514747484044; Sun,\n 31 Dec 2017 11:11:24 -0800 (PST)",
             "MIME-Version": "1.0", "Reply-To": "aa1@mail.com",
             "From": "<aa2@7IT87H1R3yks7HY3061.hastavidafi.com>",
             "Date": "Sun, 31 Dec 2017 21:11:23 +0200",
             "Subject": "FIND MY ATTACHED LETTER FROM MRS MARIA SIBANDA & REPLY TO ME +27781779673",
             "To": "<uuu@gmail.com>",
             "Content-Type": "multipart/mixed; boundary=089e0825a7a0b63ed80561a7a103",
             "x-aol-global-disposition": "S", "X-AOL-VSS-INFO": "5800.7501/124996",
             "X-AOL-VSS-CODE": "clean",
             "X-AOL-SCOLL-AUTHENTICATION": "mtaiw-aaj08.mx.aol.com ; domain : gmail.com DKIM : pass",
             "X-AOL-SCOLL-DMARC": "mtaiw-aaj08.mx.aol.com ; domain : gmail.com ; policy : none ; result : P",
             "Authentication-Results": "mx.aol.com;\n\tspf=pass (aol.com: the domain gmail.com reports 209.85.223.195 as a permitted sender.) smtp.mailfrom=gmail.com;\n\tdkim=pass (aol.com: email passed verification from the domain gmail.com.) header.i=@gmail.com;\n\tdmarc=pass (aol.com: the domain gmail.com reports that Both SPF and DKIM strictly align.) header.from=gmail.com;",
             "X-AOL-REROUTE": "YES", "x-aol-sid": "3039ac1b03c55a49365c5078", "X-AOL-IP": "209.85.223.195",
             "X-AOL-SPF": "domain : gmail.com SPF : pass",
             "Message-ID": "dshjdhs@sasa.com",
             "References": "b@ccc.com",
             "User-Agent": "bdadsa",
             "X-Mailer": "aassa"},
            {"Return-Path": "<return@academia.edu>",
             "Received": "from hastavidafi.com (hastavidafi.com. [173.82.177.231])\n        by mx.google.com with ESMTP id k33si32168844pld.22.2017.12.31.15.52.29\n        for <trblake@gmail.com>;\n        Sun, 31 Dec 2017 15:52:29 -0800 (PST)",
             "Received-SPF": "softfail (google.com: domain of transitioning return@academia.edu does not designate 173.82.177.231 as permitted sender) client-ip=173.82.177.231;",
             "Authentication-Results": "mx.google.com;\n       dkim=pass header.i=@hastavidafi.com header.s=default header.b=22xBc5jN;\n       spf=softfail (google.com: domain of transitioning return@academia.edu does not designate 173.82.177.231 as permitted sender) smtp.mailfrom=return@academia.edu",
             "DKIM-Signature": "v=1; a=rsa-sha1; c=relaxed/relaxed; s=default; d=hastavidafi.com;\n h=List-Unsubscribe:From:Date:Subject:To:Message-Id:Content-Type:Content-Transfer-Encoding; i=1Qn2114re701J6c8ijH@7IT87H1R3yks7HY3061.hastavidafi.com;\n bh=nTxOTzstHioOKjaatigYIaQodNs=;\n b=22xBc5jNpA52c1cZ2c9FYd9gjjo4KIg8i1XShfEHsBuUUg6+ys3nldv19Q1VuFTeAVxxRaWkPpRa\n   M1DtHYsjWZIdwdMmV3DudBIEG/k97jKBvDG53kp30ZTzT/pp0lcWIxQ2PB+CGHiooA7eQb3h4+5z\n   8VEIix4RH08mPAl1+dI=",
             "DomainKey-Signature": "a=rsa-sha1; c=nofws; q=dns; s=default; d=hastavidafi.com;\n b=T2/LxPeJ3fFntl3lDjZY9ojpKD3KGOoHxR0EPtNMixzgA2sjZuT8G8dvk/m4In5wWe+z+jEZ/qhr\n   I926Pf1wDEWCCf2puBAh3xYvatXyKoCtFAqipLaJBjtLu6uqb3JC2czgY/owUJC0ZGo8fq7gXLGT\n   R3n9OrpRVrjpBeKhoxU=;",
             "List-Unsubscribe": "<4NQC20m453CYJo32P48-64Tg1N209T8211IFaZJ@hastavidafi.com>",
             "From": "<aa1@gmail.com>",
             "Date": "Sun, 31 Dec 2017 15:53:18 -0800 (PDT)",
             "Subject": "=?UTF-8?B?TGV0IGJlIE5hdWdodHkgdGhpcyBDaHJpc3RtYXM=?=",
             "To": "<uuu@gmail.com>",
             "Message-Id": "<7joz19dyIWVY9562294-7Wt4X6QMfVDe0274223@hastavidafi.com>",
             "X-EMMAIL": "trblake@hastavidafi.com", "Content-Type": "text/html; charset=utf-8",
             "Content-Transfer-Encoding": "base64",
             "Message-ID": "dshjdhs@bbb.com",
             "References": "a@ddd.com",
             "X-Mailer": "ffsa"}]
    }
    
output:
{
    "Status": "200 OK"
}

```

Testing Email Header API:


POST = http://18.221.78.232/panacea-uncc/upload-email-header-for-testing/

Sample application/json: 

```
{
  "req-id": request ID,
  "email-header": {email header as json object}
}
```

Complete working sample example for TESTING:
```
POST: http://18.221.78.232/panacea-uncc/upload-email-header-for-testing/

input:
{
  "req-id": 1,
  "number-of-header": 2,
  "email-header": {
    "Return-Path": "<postnett16@gmail.com>",
    "Received": "by 10.2.159.148 with HTTP; Sun, 31 Dec 2017 11:11:23 -0800 (PST)",
    "DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=gmail.com; s=20161025;\n        h=mime-version:reply-to:from:date:message-id:subject:to;\n        bh=+tb5NQTdmm4XItRSb7nKgyzr1IRMR3P15HfouJbfHW4=;\n        b=oJ1WXlEKNgMapjLSY5ja862I1WrxxNAgJd7E3ejDiRBV9YqyK25yy4aqHpxxpZ9TVM\n         Ig1WCQ4kSWdPjv5VweLYjZUmes2m4fthvTCNZe5ywOoBOsTrnds83yj+51Qf4hyv6MK7\n         R2c9Gwt/n/+flUkLLIWm15/KoTmOF264ISXPVoX37rpRoG83DQA6xqPyeBka4nzuhwr1\n         SsJw+Uo8koU1Uc/j8THmZ5lobqWQ8h3c+ZaLbfEA0fSgm/EolrozhyRWOekAXwQqJ1sv\n         s+gWfbSIOfE2u/4nubCgL4XPKrxEcG0p6plzptr2/ditmp2LFTruKWBKzu5UUumG1lLW\n         zeFA==",
    "X-Google-DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=1e100.net; s=20161025;\n        h=x-gm-message-state:mime-version:reply-to:from:date:message-id\n         :subject:to;\n        bh=+tb5NQTdmm4XItRSb7nKgyzr1IRMR3P15HfouJbfHW4=;\n        b=jm6D/c4CzrYOOtQ1zns8kH9WzXJ3JlzIaDSA2NKbhdasozJ0IwMwytaCtXMw7+d8mG\n         O1BRqlqWsQgxcAsCdAZtO8AUzkE8K50y+Gs+8zDFCqMbx3fJz4KqRPSBXLAP5K1mnbRS\n         dJ7VTQOE9EOTLEExjKqwwlc6+52asH8GrFuzTf/wxnjPPyoKFqvLYzRjLhxLe7liMOf1\n         +XhRze8opTI2gtpEM8L5+ZSXhc+kPo7SMsr9pJyUscj0FyolQqEiQK598lpJeUHdR/tI\n         Y31BYEwo1hrhZ1XvNnB55NU5FcsRjr6tmEhk/GawpSwt+Gt1vrww+rjCtDwLFd2xza7k\n         0Uuw==",
    "X-Gm-Message-State": "AKGB3mKmk3yoWJauyXMgmV/G42IFY9zv2t4IkoH2xv9Cylu+5ZeX8Arj\n\t6sUzcAkKH8vaqb7ElDE2sROKHGyweuEpIzUJzmk=",
    "X-Google-Smtp-Source": "ACJfBovGDHF5ZZuhUIu6Cwk5Qj/ThiycrRLKknBd4qUIUNK/gqohP4qSwlLPZMBwqcQY1aRwQVh+whoUjr4bRngWBs8=",
    "X-Received": "by 10.107.81.6 with SMTP id f6mr28377175iob.20.1514747484044; Sun,\n 31 Dec 2017 11:11:24 -0800 (PST)",
    "MIME-Version": "1.0", 
    "Reply-To": "aa1@mail.com",
    "From": "<aa1@gmail.com>",
    "Date": "Sun, 31 Dec 2017 21:11:23 +0200",
    "Subject": "FIND MY ATTACHED LETTER FROM MRS MARIA SIBANDA & REPLY TO ME +27781779673",
    "To": "<uuu@gmail.com>",
    "Content-Type": "multipart/mixed; boundary=089e0825a7a0b63ed80561a7a103",
    "x-aol-global-disposition": "S", "X-AOL-VSS-INFO": "5800.7501/124996",
    "X-AOL-VSS-CODE": "clean",
    "X-AOL-SCOLL-AUTHENTICATION": "mtaiw-aaj08.mx.aol.com ; domain : gmail.com DKIM : pass",
    "X-AOL-SCOLL-DMARC": "mtaiw-aaj08.mx.aol.com ; domain : gmail.com ; policy : none ; result : P",
    "Authentication-Results": "mx.aol.com;\n\tspf=pass (aol.com: the domain gmail.com reports 209.85.223.195 as a permitted sender.) smtp.mailfrom=gmail.com;\n\tdkim=pass (aol.com: email passed verification from the domain gmail.com.) header.i=@gmail.com;\n\tdmarc=pass (aol.com: the domain gmail.com reports that Both SPF and DKIM strictly align.) header.from=gmail.com;",
    "X-AOL-REROUTE": "YES", "x-aol-sid": "3039ac1b03c55a49365c5078", "X-AOL-IP": "209.85.223.195",
    "X-AOL-SPF": "domain : gmail.com SPF : pass",
    "Message-ID": "dshj@sasa.com",
    "References": "bds@ccc.com",
    "User-Agent": "dssdsw",
    "X-Mailer": "437847"
  }
}
    
output:
{
  "score": 0.3682626715569587,
  "classicification": "malicious",
  "justification": "User Agent not comply with profile.",
  "Status": "OK"
}

```
