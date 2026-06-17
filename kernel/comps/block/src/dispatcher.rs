// SPDX-License-Identifier: MPL-2.0

//! A generic block I/O dispatcher.
//!
//! Provides [`BlockIoDispatcher`], a reusable midlayer that separates
//! request queuing / scheduling from driver-specific hardware I/O.
//! Drivers implement [`BlockRequestHandler`] and hand it to
//! [`BlockIoDispatcher::start`], which spawns a kernel thread per software
//! queue that drains the queue and invokes the handler for each request.
//!
//! The design anticipates future multi-queue support:
//!
//! * [`BlockIoDispatcher`] holds a `Vec` of software queues
//!   ([`BioQueue`]) — extending to N queues requires only passing a
//!   larger `nr_queues` to [`start`](BlockIoDispatcher::start).
//! * [`BlockRequestHandler::handle_request`] receives a `queue_id`
//!   so the handler can steer I/O to the correct hardware queue.
//! * A future [`BlockRequestHandler::try_submit_direct`] can bypass
//!   the software queue for zero-copy fast-paths.
//!
//! This eliminates the boilerplate of maintaining a [`BioRequestSingleQueue`]
//! and a consumer thread in every driver.

use ostd::task::TaskOptions;

use super::{
    bio::{BioEnqueueError, BioType, SubmittedBio},
    prelude::*,
    request_queue::{BioRequest, BioRequestSingleQueue},
};

/// Abstract software I/O queue.
///
/// A [`BioQueue`] sits between the filesystem (producer that calls
/// [`enqueue`](BioQueue::enqueue)) and a kernel thread (consumer that calls
/// [`dequeue`](BioQueue::dequeue)).  The default implementation is
/// [`BioRequestSingleQueue`], which provides FIFO ordering with
/// front-merge of contiguous requests.
pub trait BioQueue: Send + Sync + Debug {
    /// Enqueues a `SubmittedBio`.
    fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError>;

    /// Dequeues a `BioRequest`, blocking until one is available.
    fn dequeue(&self) -> BioRequest;

    /// Returns the maximum number of segments per bio for this queue.
    fn max_nr_segments_per_bio(&self) -> usize;
}

impl BioQueue for BioRequestSingleQueue {
    fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        BioRequestSingleQueue::enqueue(self, bio)
    }

    fn dequeue(&self) -> BioRequest {
        BioRequestSingleQueue::dequeue(self)
    }

    fn max_nr_segments_per_bio(&self) -> usize {
        BioRequestSingleQueue::max_nr_segments_per_bio(self)
    }
}

/// The hardware-specific I/O half that drivers must implement.
///
/// A [`BlockRequestHandler`] receives fully-formed [`BioRequest`] objects
/// from the generic dispatcher and is responsible for submitting them to
/// the underlying storage hardware (or software emulation).
///
/// `queue_id` identifies which software queue the request came from.
/// This allows the handler to steer I/O to the correct hardware queue
/// in multi-queue setups.
///
/// The handler may process requests synchronously (blocking until the
/// I/O completes) or asynchronously (submitting to a hardware queue and
/// returning immediately). Completion is signalled by calling
/// [`SubmittedBio::complete`] on each bio obtained via [`BioRequest::into_bios`].
pub trait BlockRequestHandler: Send + Sync + Debug {
    /// Process a single I/O request.
    ///
    /// `queue_id` identifies the software queue that produced this request.
    fn handle_request(&self, request: BioRequest, queue_id: usize);
}

/// A generic block device that composes a set of [`BioQueue`]s with a
/// [`BlockRequestHandler`] and a kernel thread per queue.
///
/// # Usage
///
/// ```no_run
/// use aster_block::dispatcher::{BlockIoDispatcher, BlockRequestHandler};
/// use aster_block::request_queue::BioRequest;
///
/// struct MyDriver;
///
/// impl BlockRequestHandler for MyDriver {
///     fn handle_request(&self, request: BioRequest, _queue_id: usize) {
///         // submit to hardware ...
///     }
/// }
///
/// let handler = Arc::new(MyDriver);
/// let dispatcher = BlockIoDispatcher::start(handler, 1, 256);
/// dispatcher.enqueue(...);
/// ```
#[derive(Debug)]
pub struct BlockIoDispatcher {
    handler: Arc<dyn BlockRequestHandler>,
    software_queues: Vec<Arc<dyn BioQueue>>,
}

impl BlockIoDispatcher {
    /// Creates a new dispatcher with `nr_queues` software queues and spawns
    /// a kernel thread for each queue that continuously dequeues requests
    /// and forwards them to `handler`.
    ///
    /// `max_nr_segments_per_bio` is passed to each underlying
    /// [`BioRequestSingleQueue`].
    ///
    /// For single-queue usage (current default), pass `nr_queues: 1`.
    pub fn start<H>(
        handler: Arc<H>,
        nr_queues: usize,
        max_nr_segments_per_bio: usize,
    ) -> Arc<Self>
    where
        H: BlockRequestHandler + 'static,
    {
        let queues: Vec<Arc<dyn BioQueue>> = (0..nr_queues)
            .map(|_| {
                Arc::new(BioRequestSingleQueue::with_max_nr_segments_per_bio(
                    max_nr_segments_per_bio,
                )) as Arc<dyn BioQueue>
            })
            .collect();

        let dispatcher = Arc::new(Self {
            handler: handler as Arc<dyn BlockRequestHandler>,
            software_queues: queues,
        });

        for (queue_id, queue) in dispatcher.software_queues.iter().enumerate() {
            let queue = queue.clone();
            let cloned = dispatcher.clone();
            let _ = TaskOptions::new(move || {
                loop {
                    let request = queue.dequeue();
                    ostd::debug!("Handle Request: {:?}", request);
                    match request.type_() {
                        BioType::Read | BioType::Write | BioType::Flush => {
                            cloned.handler.handle_request(request, queue_id);
                        }
                    }
                }
            })
            .spawn()
            .expect("failed to spawn block dispatcher kthread");
        }

        dispatcher
    }

    /// Enqueues a `SubmittedBio` into queue 0.
    ///
    /// Future multi-queue support will allow routing to a specific queue
    /// (e.g. via a hash on sector number or CPU affinity).
    pub fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        self.software_queues[0].enqueue(bio)
    }

    /// Returns the maximum number of segments per bio.
    pub fn max_nr_segments(&self) -> usize {
        self.software_queues[0].max_nr_segments_per_bio()
    }
}
