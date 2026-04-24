-- Migration: Email log table to track all sent emails

IF OBJECT_ID('dbo.email_log','U') IS NULL BEGIN
CREATE TABLE email_log (
    id          INT          IDENTITY(1,1) PRIMARY KEY,
    sent_at     DATETIME     NOT NULL DEFAULT GETDATE(),
    subject     NVARCHAR(500) NULL,
    recipients  NVARCHAR(2000) NULL,
    alarm_type  VARCHAR(100) NULL,
    mail_type   VARCHAR(100) NULL,
    status      VARCHAR(20)  NOT NULL DEFAULT 'sent',
    error_msg   NVARCHAR(1000) NULL
);
END

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_email_log_sent_at' AND object_id=OBJECT_ID('email_log'))
    CREATE INDEX idx_email_log_sent_at ON email_log(sent_at DESC);
