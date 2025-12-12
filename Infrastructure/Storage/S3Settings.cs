// Infrastructure/Storage/S3Settings.cs
namespace backend.Infrastructure.Storage
{
    public class S3Settings
    {
        public string BucketName { get; set; }
        public string RegionEndpoint { get; set; }
        public string AccessKey { get; set; }
        public string SecretKey { get; set; }
        public bool UseHttp { get; set; }
        public bool ForcePathStyle { get; set; }
        public string ServiceURL { get; set; }
        public int PresignedUrlExpiryHours { get; set; } = 24;
    }

    public class FileStorageSettings
    {
        public string StorageType { get; set; } = "S3";
        public string BaseUrl { get; set; }
        public string CdnUrl { get; set; }
        public bool EnableCdn { get; set; }
        public bool EnableCompression { get; set; } = true;
        public bool EnableEncryption { get; set; } = true;
        public string LocalStoragePath { get; set; } = "wwwroot/uploads";

        public Dictionary<string, string[]> AllowedFileTypes { get; set; } = new();
        public Dictionary<string, int> MaxFileSizes { get; set; } = new(); // In MB
        public Dictionary<string, string> Paths { get; set; } = new();
    }

    public enum FileTypeCategory
    {
        ProfilePicture,
        CompanyLogo,
        CV,
        SupportingDocument,
        JobAttachment
    }

    public class FileUploadResult
    {
        public string FileUrl { get; set; }
        public string FileName { get; set; }
        public string OriginalFileName { get; set; }
        public long FileSize { get; set; }
        public string ContentType { get; set; }
        public string FileKey { get; set; }
        public string StoragePath { get; set; }
        public DateTime UploadedAt { get; set; }
        public Dictionary<string, string> Metadata { get; set; } = new();
    }
}