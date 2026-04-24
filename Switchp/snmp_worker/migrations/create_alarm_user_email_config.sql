-- Migration: Per-user per-alarm-type email notification settings
-- Each row means: user X wants/does not want emails for alarm_type Y

IF OBJECT_ID('dbo.alarm_user_email_config','U') IS NULL BEGIN
CREATE TABLE alarm_user_email_config (
    alarm_type      VARCHAR(100) NOT NULL,
    user_id         INT          NOT NULL,
    email_enabled   BIT          NOT NULL DEFAULT 1,
    CONSTRAINT PK_alarm_user_email_config PRIMARY KEY (alarm_type, user_id)
);
END

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_auec_alarm_type' AND object_id=OBJECT_ID('alarm_user_email_config'))
    CREATE INDEX idx_auec_alarm_type ON alarm_user_email_config(alarm_type);

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='idx_auec_user_id' AND object_id=OBJECT_ID('alarm_user_email_config'))
    CREATE INDEX idx_auec_user_id ON alarm_user_email_config(user_id);
