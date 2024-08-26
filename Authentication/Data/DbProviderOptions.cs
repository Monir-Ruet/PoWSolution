namespace Authentication.Data;

public class DbProviderOptions
{
    public string DbSchema { get; set; } = "dbo";

    public string? ConnectionString { get; set; }
}