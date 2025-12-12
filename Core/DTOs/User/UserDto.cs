namespace backend.Core.DTOs.User
{
    public class UserDto
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string? PhoneNumber { get; set; }
        public string UserType { get; set; }
        public bool EmailVerified { get; set; }
        public string? ProfilePictureUrl { get; set; }
        public string? CompanyName { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
    }

    public class UserProfileDto : UserDto
    {
        public JobSeekerProfileDto? JobSeekerProfile { get; set; }
        public RecruiterProfileDto? RecruiterProfile { get; set; }
        public CompanyProfileDto? CompanyProfile { get; set; }
    }

    public class JobSeekerProfileDto
    {
        public int Id { get; set; }
        public string? Headline { get; set; }
        public string? Summary { get; set; }
        public string? CurrentPosition { get; set; }
        public string? CurrentCompany { get; set; }
        public string? Location { get; set; }
        public string? Country { get; set; }
        public string? LinkedInUrl { get; set; }
        public string? GitHubUrl { get; set; }
        public string? PortfolioUrl { get; set; }
        public decimal? DesiredSalary { get; set; }
        public string? DesiredSalaryCurrency { get; set; }
        public List<string> Skills { get; set; } = new();
        public List<string> Languages { get; set; } = new();
        public string? CvUrl { get; set; }
        public string? CvFileName { get; set; }
        public DateTime? CvUploadDate { get; set; }
        public bool IsOpenToWork { get; set; }
        public bool IsOpenToRemote { get; set; }
    }

    public class RecruiterProfileDto
    {
        public int Id { get; set; }
        public string? Department { get; set; }
        public string? Bio { get; set; }
        public int? YearsOfExperience { get; set; }
        public string? Specializations { get; set; }
        public CompanyProfileDto? Company { get; set; }
    }

    public class CompanyProfileDto
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string? Description { get; set; }
        public string? Industry { get; set; }
        public string? Website { get; set; }
        public string? LogoUrl { get; set; }
        public string? Size { get; set; }
        public string? Headquarters { get; set; }
        public int? FoundedYear { get; set; }
        public string? TechStack { get; set; }
        public string? Benefits { get; set; }
    }
}