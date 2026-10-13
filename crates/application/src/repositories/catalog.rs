//! Named caller: NdsClient::github_repository_page. The composition owns vault
//! selection/fence validation, HTTP, clocks, deadlines and cancellation. This
//! use case returns one validated page and never updates a persistent registry.
use nddev_device_sync_domain::{modules::ModuleError, repositories::catalog::*};
use std::future::Future;

/// Browser futures may remain local; native adapters supply their Send future.
pub trait ReadGithubCatalogPage {
    type Error: From<ModuleError>;
    type Cancellation;
    fn read_page(
        &self,
        request: &CatalogPageRequest,
        cancellation: &Self::Cancellation,
    ) -> impl Future<Output = Result<ProviderRepositoryPage, Self::Error>>;
}

pub async fn repository_page<P: ReadGithubCatalogPage>(
    port: &P,
    selection: CredentialSelection,
    after: Option<&CatalogCursor>,
    cancellation: &P::Cancellation,
) -> Result<RepositoryPage, P::Error> {
    let request = CatalogPageRequest::new(selection, after)?;
    let page = port.read_page(&request, cancellation).await?;
    Ok(page.into_page(&request)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        task::{Context, Poll, Waker},
    };

    // Pure ready-future input, not HTTP/provider/runtime acceptance.
    struct Input {
        page: RefCell<Option<ProviderRepositoryPage>>,
        calls: Cell<usize>,
    }
    impl ReadGithubCatalogPage for Input {
        type Error = ModuleError;
        type Cancellation = ();
        fn read_page(
            &self,
            request: &CatalogPageRequest,
            _: &(),
        ) -> impl Future<Output = Result<ProviderRepositoryPage, ModuleError>> {
            assert!((1..=MAX_CATALOG_PAGES).contains(&request.page()));
            self.calls.set(self.calls.get() + 1);
            std::future::ready(
                self.page
                    .borrow_mut()
                    .take()
                    .ok_or(ModuleError::Unavailable),
            )
        }
    }
    fn run<T>(future: impl Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("pure input must be ready"),
        }
    }
    fn selection(pending: &str) -> CredentialSelection {
        CredentialSelection::new("credential".into(), 0, Some(pending.into())).unwrap()
    }
    fn provider() -> ProviderRepositoryPage {
        ProviderRepositoryPage {
            principal: GithubOwner {
                id: GithubAccountId::new(1).unwrap(),
                kind: GithubOwnerKind::User,
                login: "user".into(),
            },
            repositories: vec![],
            observed_at_ms: 100,
            has_more: true,
        }
    }
    #[test]
    fn stale_selection_is_denied_before_the_read_port_and_errors_do_not_become_empty_pages() {
        let input = Input {
            page: RefCell::new(Some(provider())),
            calls: Cell::new(0),
        };
        let first = run(repository_page(&input, selection("operation-a"), None, &())).unwrap();
        let CatalogContinuation::More(cursor) = first.continuation else {
            panic!("cursor required")
        };
        assert!(matches!(
            run(repository_page(
                &input,
                selection("operation-b"),
                Some(&cursor),
                &()
            )),
            Err(ModuleError::InvalidInput)
        ));
        assert_eq!(input.calls.get(), 1);
        assert!(matches!(
            run(repository_page(
                &input,
                selection("operation-a"),
                Some(&cursor),
                &()
            )),
            Err(ModuleError::Unavailable)
        ));
    }
    #[test]
    fn invalid_provider_facts_are_rejected_after_the_read_port() {
        let mut page = provider();
        page.observed_at_ms = 0;
        let input = Input {
            page: RefCell::new(Some(page)),
            calls: Cell::new(0),
        };
        assert!(matches!(
            run(repository_page(&input, selection("operation-a"), None, &())),
            Err(ModuleError::InvalidResponse)
        ));
        assert_eq!(input.calls.get(), 1);
    }
}
