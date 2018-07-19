USE MASTER

BEGIN --Getting Ready
 raiserror ('Getting Ready', 10,1) with nowait
IF OBJECT_ID('tempdb..#STIGResults') IS NOT NULL
    DROP TABLE #STIGResults
--Create Temp results table
Create Table #STIGResults (
	STIG varchar(500),
	ServerName varchar(100),  
	DatabaseName varchar(100), 
	Result varchar(100), 
	Notes varchar(500),
	RunTimeStamp datetime
	)
--Create Script variables
		DECLARE @Database varchar(20)
		DECLARE @Command nvarchar(2000) 
		DECLARE @HitCount int = 0
END --Ready

BEGIN --V-79061- SQL Server 2016 Database-Contained Databases, Mixed Mode Authentication, and Database SQL Logins
 raiserror ('Starting V-79061-1', 10,1) with nowait
--V-79061 Check 1: Determine if SQL Server is configured to allow the use of contained databases.
Declare @V790611 table([Name] varchar(50), [Min] int, [max] int, [config] int, [run] int)
insert into @V790611 EXEC sp_configure 'contained database authentication'
Insert into #STIGResults
	Select 'V-79061-1-Contained Databases' as STIG, 
		@@SERVERNAME AS ServerName,
		'NA' AS DatabaseName,
		CASE config
			WHEN 0 THEN 'Not A Finding' 
			WHEN 1 THEN 'FINDING' 
		END AS Result,
		CASE config	
			WHEN 0 THEN 'Contained Databases are disabled' 
			WHEN 1 THEN 'Contained Databases are enabled' 
		END AS Notes, 
		SYSDATETIME() as RunTimeStamp
	FROM @V790611;
--V-79061 Check 2: Determine whether SQL Server is configured to use only Windows authentication. 
 raiserror ('Starting V-79061-2', 10,1) with nowait
Insert into #STIGResults
	Select 'V-79061-2-Windows or Mixed Authentication' as STIG,
		@@SERVERNAME AS ServerName,
		'NA' AS DatabaseName,
		CASE SERVERPROPERTY('IsIntegratedSecurityOnly') 
			WHEN 1 THEN 'Not A Finding' 
			WHEN 0 THEN 'CHECK DOCUMENTATION' 
		END as Result,
		CASE SERVERPROPERTY('IsIntegratedSecurityOnly') 
			WHEN 1 THEN 'Windows Authentication Only' 
			WHEN 0 THEN 'Windows and SQL Server Authentication. Documentation is required for Mixed Mode authentication, or it must be disabled.' 
		END as Notes, 
		SYSDATETIME() as RunTimeStamp;  
--V-79061 Check 3: If Server is in Mixed Authentication Mode, Determine the accounts (SQL Logins) actually managed by SQL Server that must be documented. 
 raiserror ('Starting V-79061-3', 10,1) with nowait
IF (SERVERPROPERTY('IsIntegratedSecurityOnly') = 0)
	BEGIN
		SELECT @HitCount=0, @Database='', @Command=''
		Declare DB_Users_Cursor CURSOR FOR
			SELECT name from Sys.databases 
		OPEN DB_Users_Cursor
		FETCH NEXT FROM DB_Users_Cursor INTO @Database
		WHILE @@FETCH_STATUS = 0
		BEGIN 
				SELECT @Command = 'Insert into #STIGResults 
									SELECT ''V-79061-3-Database SQL Logins'' as STIG, 
										@@SERVERNAME AS ServerName, 
										'''+@Database+''' AS DatabaseName, 
										''CHECK DOCUMENTATION'' as Result,  
										'''+@Database+''' +''_''+Name+ ''  Database SQL Login must be documented as authorized.'' as Notes, 
										SYSDATETIME() as RunTimeStamp 
										FROM '+@Database+'.sys.database_principals 
										WHERE type_desc = ''SQL_USER'' AND authentication_type_desc = ''DATABASE'''
				EXEC sp_executesql @Command 
				SELECT @HitCount = @HitCount+@@ROWCOUNT
			FETCH NEXT FROM DB_Users_Cursor INTO @Database
		END
		CLOSE DB_Users_Cursor
		DEALLOCATE DB_Users_Cursor
		IF (@HitCount = 0)
			BEGIN
				Insert into #STIGResults
					Select 'V-79061-3-Database SQL Logins' as STIG,
					@@SERVERNAME AS ServerName,
					'NA' AS DatabaseName,
					'Not A Finding' as Result, 
					'No Database SQL Logins found' as Notes, 
					SYSDATETIME() as RunTimeStamp
			END
	END
	ELSE
		Insert into #STIGResults
		Select 'V-79061-3-Database SQL Logins' as STIG,
				@@SERVERNAME AS ServerName,
				'NA' AS DatabaseName,
				'Not A Finding' as Result, 
				'Windows Authentication Only' as Notes, 
				SYSDATETIME() as RunTimeStamp
END  --V-79061

Select * from #STIGResults
