# Sample SQL Queries
The following queries can be used in `analyzer.py` to change the output of the program to the desired data. Feel free to use any queries not on this list.

Show all failed logins
```sql
SELECT *
FROM login_events
WHERE status = 'failed';
```

Count failures by IP address
```sql
SELECT ip_address, COUNT(*) AS failed_attempts
FROM login_events
WHERE status = 'failed'
GROUP BY ip_address
ORDER BY failed_attempts DESC;
```

Find usernames with failed logins
```sql
SELECT username, COUNT(*) AS failed_attempts
FROM login_events
WHERE status = 'failed'
GROUP BY username
ORDER BY failed_attempts DESC;
```